// src/index.ts
import { Elysia, t } from "elysia";
import { cors } from "@elysiajs/cors";
import { jwt } from "@elysiajs/jwt";
import { cookie } from "@elysiajs/cookie";
import { compare, hash } from "bcrypt";
import { db } from "./db";
import { eq } from "drizzle-orm";
import { users, sessions } from "./db/schema";
import { logger } from "./utils/logger";
import { security } from "./utils/security";
import type { SecurityContext } from "./utils/security";
import * as dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Constants
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your-refresh-secret";
const SALT_ROUNDS = 10;

// Define types for our API responses
type ApiErrorCode = "VALIDATION_ERROR" | "NOT_FOUND" | "INTERNAL_ERROR" | "UNAUTHORIZED";

type ApiSuccessResponse<T> = {
  success: true;
  data: T;
  error?: never;
};

type ApiErrorResponse = {
  success: false;
  data?: never;
  error: string;
  code: ApiErrorCode;
};

type ApiResponse<T> = ApiSuccessResponse<T> | ApiErrorResponse;

// Auth types
type SignupRequest = {
  email: string;
  password: string;
};

type LoginRequest = SignupRequest;

type UserResponse = {
  userId: string;
  email: string;
};

type AuthResponse = UserResponse;

// JWT payload type
interface JWTPayload {
  userId: string;
  email: string;
}

// Request context types
interface AuthContext {
  jwt: {
    verify: (token: string) => Promise<JWTPayload | null>;
    sign: (payload: JWTPayload) => Promise<string>;
  };
  cookie: {
    auth?: string;
    refresh?: string;
  };
  request: Request;
}

// Auth function type
interface AuthFunction {
  auth: () => Promise<JWTPayload | null>;
}

// Response types
interface ElysiaResponse {
  status?: number;
  body?: any;
}

interface ElysiaSet {
  status?: number;
  headers?: Record<string, string>;
}

// Error type
interface ElysiaError {
  code: string;
  error: Error;
  request: Request;
}

// Create the app instance
const app = new Elysia()
  .use(cors())
  .use(
    jwt({
      name: "jwt",
      secret: JWT_SECRET,
      exp: "15m"
    })
  )
  .use(
    jwt({
      name: "refreshJwt",
      secret: REFRESH_SECRET,
      exp: "7d"
    })
  )
  .use(cookie())
  // Request logging middleware
  .derive(async ({ request }: { request: Request }) => {
    // Enrich request with security context
    const securityContext = await security.enrichRequest(request);

    // Check if IP is blocked
    if (await security.isIPBlocked(securityContext.ip)) {
      throw new Error("IP is blocked");
    }

    // Check rate limit
    if (!securityContext.rateLimit.remaining) {
      throw new Error("Rate limit exceeded");
    }

    // Log request with security context
    const requestId = await logger.request(request, { security: securityContext });

    return { requestId, security: securityContext };
  })
  // Response logging middleware
  .onResponse(({ response, set, requestId }: { response: ElysiaResponse; set: ElysiaSet; requestId: string }) => {
    if (response && "status" in response) {
      logger.response(response.status || 200, response.body, requestId);
    } else {
      const status = set.status || 200;
      logger.response(status, response, requestId);
    }
  })
  // Auth middleware
  .derive(({ jwt, cookie, request, setCookie }: AuthContext & { setCookie: any }) => {
    return {
      auth: async () => {
        // Try access token first
        const accessToken = cookie.auth;
        if (accessToken) {
          try {
            const payload = await jwt.verify(accessToken);
            if (payload) {
              const user = await db.query.users.findFirst({
                where: eq(users.id, payload.userId)
              });
              if (user) return payload;
            }
          } catch {
            // Access token invalid, try refresh token
          }
        }

        // Try refresh token
        const refreshToken = cookie.refresh;
        if (refreshToken) {
          try {
            const session = await db.query.sessions.findFirst({
              where: eq(sessions.refreshToken, refreshToken)
            });

            if (session && new Date() < session.expiresAt) {
              const payload = await jwt.verify(refreshToken);
              if (payload && typeof payload === "object") {
                // Generate new access token
                const newAccessToken = await jwt.sign(payload as JWTPayload);

                // Set new access token cookie
                setCookie("auth", newAccessToken, {
                  httpOnly: true,
                  secure: process.env.NODE_ENV === "production",
                  sameSite: "strict",
                  maxAge: 900000 // 15 minutes
                });

                return payload;
              }
            }
          } catch {
            // Refresh token invalid
          }
        }

        return null;
      }
    };
  })
  .onError(async ({ code, error, request }: ElysiaError): Promise<ApiErrorResponse> => {
    await logger.error("Request failed", {
      code,
      error,
      path: request.url,
      method: request.method
    });
    return {
      success: false,
      error: error.message,
      code: (code === "VALIDATION"
        ? "VALIDATION_ERROR"
        : code === "NOT_FOUND"
        ? "NOT_FOUND"
        : "INTERNAL_ERROR") as ApiErrorCode
    };
  })
  // Public routes
  .get(
    "/health",
    (): ApiResponse<{ status: string; timestamp: string }> => ({
      success: true,
      data: {
        status: "healthy",
        timestamp: new Date().toISOString()
      }
    })
  )
  // Auth routes
  .post(
    "/auth/signup",
    {
      body: t.Object({
        email: t.String({ format: "email" }),
        password: t.String({ minLength: 8 })
      })
    },
    async ({
      body,
      jwt,
      refreshJwt,
      setCookie
    }: {
      body: SignupRequest;
      jwt: AuthContext["jwt"];
      refreshJwt: AuthContext["jwt"];
      setCookie: any;
    }): Promise<ApiResponse<UserResponse>> => {
      try {
        // Check if user exists
        const existingUser = await db.query.users.findFirst({
          where: eq(users.email, body.email)
        });

        if (existingUser) {
          await logger.warn("Signup attempt with existing email", { email: body.email });
          return {
            success: false,
            error: "Email already registered",
            code: "VALIDATION_ERROR"
          };
        }

        const hashedPassword = await hash(body.password, SALT_ROUNDS);

        // Create new user
        const [user] = await db
          .insert(users)
          .values({
            email: body.email,
            password: hashedPassword
          })
          .returning();

        await logger.info("User created successfully", { userId: user.id, email: user.email });

        const accessToken = await jwt.sign({ userId: user.id, email: user.email });
        const refreshToken = await refreshJwt.sign({ userId: user.id, email: user.email });

        // Store refresh token
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now

        await db.insert(sessions).values({
          userId: user.id,
          refreshToken,
          expiresAt
        });

        // Set HTTP-only cookies
        setCookie("auth", accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 900000 // 15 minutes
        });

        setCookie("refresh", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 604800000 // 7 days
        });

        return {
          success: true,
          data: {
            userId: user.id,
            email: user.email
          }
        };
      } catch (error) {
        await logger.error("Signup failed", { error, email: body.email });
        throw error;
      }
    }
  )
  .post(
    "/auth/login",
    {
      body: t.Object({
        email: t.String({ format: "email" }),
        password: t.String()
      })
    },
    async ({
      body,
      jwt,
      refreshJwt,
      setCookie,
      security: securityContext
    }: {
      body: LoginRequest;
      jwt: AuthContext["jwt"];
      refreshJwt: AuthContext["jwt"];
      setCookie: any;
      security: SecurityContext;
    }): Promise<ApiResponse<UserResponse>> => {
      try {
        const user = await db.query.users.findFirst({
          where: eq(users.email, body.email)
        });

        if (!user) {
          await security.trackSuspiciousActivity(securityContext.ip, "login_invalid_email");
          await logger.warn("Login attempt with non-existent email", {
            email: body.email,
            security: securityContext
          });
          return {
            success: false,
            error: "Invalid credentials",
            code: "UNAUTHORIZED"
          };
        }

        const validPassword = await compare(body.password, user.password);
        if (!validPassword) {
          await security.trackSuspiciousActivity(securityContext.ip, "login_invalid_password");
          await logger.warn("Login attempt with invalid password", {
            email: body.email,
            security: securityContext
          });
          return {
            success: false,
            error: "Invalid credentials",
            code: "UNAUTHORIZED"
          };
        }

        await logger.info("User logged in successfully", {
          userId: user.id,
          email: user.email,
          security: securityContext
        });

        const accessToken = await jwt.sign({ userId: user.id, email: user.email });
        const refreshToken = await refreshJwt.sign({ userId: user.id, email: user.email });

        // Store refresh token
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now

        await db.insert(sessions).values({
          userId: user.id,
          refreshToken,
          expiresAt
        });

        // Set HTTP-only cookies
        setCookie("auth", accessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 900000 // 15 minutes
        });

        setCookie("refresh", refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 604800000 // 7 days
        });

        return {
          success: true,
          data: {
            userId: user.id,
            email: user.email
          }
        };
      } catch (error) {
        await logger.error("Login failed", {
          error,
          email: body.email,
          security: securityContext
        });
        throw error;
      }
    }
  )
  .post(
    "/auth/refresh",
    async ({
      cookie,
      jwt,
      setCookie
    }: {
      cookie: { refresh?: string };
      jwt: AuthContext["jwt"];
      setCookie: any;
    }): Promise<ApiResponse<{ message: string }>> => {
      const refreshToken = cookie.refresh;
      if (!refreshToken) {
        await logger.warn("Refresh token attempt without token");
        return {
          success: false,
          error: "No refresh token provided",
          code: "UNAUTHORIZED"
        };
      }

      try {
        const session = await db.query.sessions.findFirst({
          where: eq(sessions.refreshToken, refreshToken)
        });

        if (!session || new Date() > session.expiresAt) {
          if (session) {
            await db.delete(sessions).where(eq(sessions.id, session.id));
            await logger.info("Deleted expired session", { sessionId: session.id });
          }
          await logger.warn("Invalid or expired refresh token attempt");
          throw new Error("Invalid or expired refresh token");
        }

        const payload = await jwt.verify(refreshToken);
        if (!payload || typeof payload !== "object") {
          await logger.warn("Invalid token payload");
          throw new Error("Invalid token");
        }

        const newAccessToken = await jwt.sign(payload as JWTPayload);
        await logger.info("Access token refreshed", { userId: (payload as JWTPayload).userId });

        // Set new access token cookie
        setCookie("auth", newAccessToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: 900000 // 15 minutes
        });

        return {
          success: true,
          data: { message: "Token refreshed successfully" }
        };
      } catch (error) {
        await logger.error("Token refresh failed", { error });
        return {
          success: false,
          error: error instanceof Error ? error.message : "Invalid refresh token",
          code: "UNAUTHORIZED"
        };
      }
    }
  )
  .post(
    "/auth/logout",
    async ({ cookie, setCookie }: { cookie: { auth?: string; refresh?: string }; setCookie: any }) => {
      const refreshToken = cookie.refresh;
      if (refreshToken) {
        try {
          // Delete the session
          const session = await db.query.sessions.findFirst({
            where: eq(sessions.refreshToken, refreshToken)
          });

          if (session) {
            await db.delete(sessions).where(eq(sessions.id, session.id));
            await logger.info("User logged out", { userId: session.userId });
          }
        } catch (error) {
          await logger.error("Error during logout", { error });
          // Ignore errors during logout
        }
      } else {
        await logger.warn("Logout attempt without refresh token");
      }

      // Clear cookies
      setCookie("auth", "", { maxAge: 0 });
      setCookie("refresh", "", { maxAge: 0 });

      return {
        success: true,
        data: { message: "Logged out successfully" }
      };
    }
  )
  // Protected routes
  .get("/api/protected", async ({ auth }: AuthFunction): Promise<ApiResponse<{ message: string }>> => {
    const user = await auth();
    if (!user) {
      return {
        success: false,
        error: "Unauthorized",
        code: "UNAUTHORIZED"
      };
    }

    return {
      success: true,
      data: {
        message: `Hello ${user.email}! This is a protected route.`
      }
    };
  })
  // Example protected resource route
  .get("/api/me", async ({ auth }: AuthFunction): Promise<ApiResponse<UserResponse>> => {
    const user = await auth();
    if (!user) {
      return {
        success: false,
        error: "Unauthorized",
        code: "UNAUTHORIZED"
      };
    }

    return {
      success: true,
      data: {
        userId: user.userId,
        email: user.email
      }
    };
  });

// Handle shutdown gracefully
process.on("SIGTERM", async () => {
  await logger.flush();
  process.exit(0);
});

process.on("SIGINT", async () => {
  await logger.flush();
  process.exit(0);
});

export type App = typeof app;
export default app;
