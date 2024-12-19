import { Logtail } from "@logtail/node";
import { LogLevel } from "@logtail/types";

// Initialize Logtail with better error handling
let logtail: Logtail | null = null;
try {
  const token = process.env.LOGTAIL_SOURCE_TOKEN;
  if (!token) {
    console.warn("LOGTAIL_SOURCE_TOKEN is not set. Falling back to console logging only.");
  } else {
    logtail = new Logtail(token);
    console.log("Logtail initialized");
  }
} catch (error) {
  console.error("Failed to initialize Logtail:", error);
}

// Log levels mapping
const levels = {
  debug: LogLevel.Debug,
  info: LogLevel.Info,
  warn: LogLevel.Warn,
  error: LogLevel.Error
} as const;

// Logger interface
interface LogContext {
  [key: string]: any;
}

interface RequestTimer {
  url: string;
  startTime: number;
  endTime?: number;
}

class Logger {
  private static instance: Logger;
  private env: string;
  private requestTimers: Map<string, RequestTimer>;

  private constructor() {
    this.env = process.env.NODE_ENV || "development";
    this.requestTimers = new Map();
  }

  public static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  private formatMessage(message: string, context?: LogContext): string {
    return context ? `${message} ${JSON.stringify(context)}` : message;
  }

  private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
    const sensitiveHeaders = ["authorization", "cookie", "x-api-key"];
    return Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [
        key,
        sensitiveHeaders.includes(key.toLowerCase()) ? "[REDACTED]" : value
      ])
    );
  }

  private async log(level: keyof typeof levels, message: string, context?: LogContext) {
    const timestamp = new Date().toISOString();
    const formattedMessage = this.formatMessage(message, context);

    // Always console log in development
    if (this.env === "development") {
      console[level](`[${timestamp}] ${level.toUpperCase()}: ${formattedMessage}`);
    }

    // Send to BetterStack if available
    if (logtail) {
      try {
        await logtail[level](formattedMessage, {
          context: {
            ...context,
            environment: this.env,
            timestamp
          }
        });
        // Flush logs immediately in development for better debugging
        if (this.env === "development") {
          await logtail.flush();
        }
      } catch (error) {
        console.error("Failed to send log to BetterStack:", error);
        // Fallback to console in production if BetterStack fails
        if (this.env === "production") {
          console[level](`[${timestamp}] ${level.toUpperCase()}: ${formattedMessage}`);
        }
      }
    }
  }

  public async debug(message: string, context?: LogContext) {
    await this.log("debug", message, context);
  }

  public async info(message: string, context?: LogContext) {
    await this.log("info", message, context);
  }

  public async warn(message: string, context?: LogContext) {
    await this.log("warn", message, context);
  }

  public async error(message: string, context?: LogContext) {
    if (context?.error instanceof Error) {
      context.errorDetails = {
        message: context.error.message,
        name: context.error.name,
        stack: context.error.stack
      };
      delete context.error;
    }
    await this.log("error", message, context);
  }

  public async request(req: Request, context?: LogContext): Promise<string> {
    const requestId = crypto.randomUUID();
    const url = new URL(req.url);

    this.requestTimers.set(requestId, {
      url: url.pathname,
      startTime: performance.now()
    });

    // Convert Headers to a plain object
    const headerObj: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      headerObj[key] = value;
    });

    const requestContext = {
      requestId,
      method: req.method,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      headers: this.sanitizeHeaders(headerObj),
      ...context
    };

    await this.info("Incoming request", requestContext);
    return requestId;
  }

  public async response(status: number, body: any, requestId?: string, context?: LogContext) {
    let duration: number | undefined;

    if (requestId) {
      const timer = this.requestTimers.get(requestId);
      if (timer) {
        timer.endTime = performance.now();
        duration = timer.endTime - timer.startTime;
        this.requestTimers.delete(requestId);
      }
    }

    // Handle different response types
    let responseBody = body;
    if (body && typeof body === "object") {
      if ("body" in body) {
        responseBody = body.body;
      } else if ("response" in body) {
        responseBody = body.response;
      }
    }

    const responseContext = {
      requestId,
      status,
      duration: duration ? `${duration.toFixed(2)}ms` : undefined,
      body: this.sanitizeResponse(responseBody),
      ...context
    };

    await this.info("Outgoing response", responseContext);
  }

  private sanitizeResponse(body: any): any {
    if (!body) return body;

    // Don't log large responses
    if (typeof body === "string" && body.length > 1000) {
      return `[Response too large: ${body.length} chars]`;
    }

    // Redact sensitive fields
    if (typeof body === "object") {
      const sensitiveFields = ["password", "token", "secret", "apiKey"];
      return JSON.parse(
        JSON.stringify(body, (key, value) => (sensitiveFields.includes(key.toLowerCase()) ? "[REDACTED]" : value))
      );
    }

    return body;
  }

  // Cleanup old request timers periodically
  public startCleanup(intervalMs: number = 300000) {
    // 5 minutes
    setInterval(() => {
      const now = performance.now();
      for (const [id, timer] of this.requestTimers.entries()) {
        if (now - timer.startTime > intervalMs) {
          this.requestTimers.delete(id);
        }
      }
    }, intervalMs);
  }

  // Flush all pending logs
  public async flush(): Promise<void> {
    if (logtail) {
      try {
        await logtail.flush();
      } catch (error) {
        console.error("Failed to flush logs:", error);
      }
    }
  }
}

export const logger = Logger.getInstance();
// Start cleanup of old request timers
logger.startCleanup();
