import { Redis } from "@upstash/redis";
import geoip from "geoip-lite";
import { UAParser } from "ua-parser-js";
import { logger } from "./logger";

// Initialize Upstash Redis client
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!
});

// Initialize UA Parser
const uaParser = new UAParser();

// Rate limit configuration
const RATE_LIMIT_WINDOW = 60; // 1 minute
const RATE_LIMIT_MAX = 60; // requests per window

export interface GeoLocation {
  country?: string;
  region?: string;
  city?: string;
  ll?: [number, number]; // latitude, longitude
}

export interface SecurityContext {
  ip: string;
  userAgent: {
    browser?: string;
    os?: string;
    device?: string;
  };
  geolocation?: GeoLocation;
  rateLimit: {
    remaining: number;
    reset: number;
  };
}

export class SecurityService {
  private static instance: SecurityService;

  private constructor() {}

  public static getInstance(): SecurityService {
    if (!SecurityService.instance) {
      SecurityService.instance = new SecurityService();
    }
    return SecurityService.instance;
  }

  private getGeoLocation(ip: string): GeoLocation | undefined {
    try {
      const geo = geoip.lookup(ip);
      if (!geo) return undefined;

      return {
        country: geo.country,
        region: geo.region,
        city: geo.city,
        ll: geo.ll
      };
    } catch (error) {
      logger.error("Failed to get geolocation", { error, ip });
      return undefined;
    }
  }

  private getUserAgent(userAgentString: string) {
    try {
      uaParser.setUA(userAgentString);
      const result = uaParser.getResult();
      return {
        browser: result.browser.name,
        os: result.os.name,
        device: result.device.type || "desktop"
      };
    } catch (error) {
      logger.error("Failed to parse user agent", { error, userAgentString });
      return {};
    }
  }

  public async checkRateLimit(
    ip: string,
    path: string
  ): Promise<{ allowed: boolean; remaining: number; reset: number }> {
    const now = Math.floor(Date.now() / 1000);
    const key = `rate_limit:${ip}:${path}`;

    try {
      // Use Redis transaction to ensure atomic operations
      const multi = redis.multi();
      multi.incr(key);
      multi.ttl(key);

      const results = await multi.exec();
      const count = results?.[0] as number;
      const ttl = results?.[1] as number;

      // If this is the first request, set expiry
      if (count === 1) {
        await redis.expire(key, RATE_LIMIT_WINDOW);
      }

      const reset = now + (ttl === -1 ? RATE_LIMIT_WINDOW : ttl);
      const remaining = Math.max(0, RATE_LIMIT_MAX - count);

      return {
        allowed: count <= RATE_LIMIT_MAX,
        remaining,
        reset
      };
    } catch (error) {
      logger.error("Rate limit check failed", { error, ip, path });
      // Fail open in case of Redis error
      return {
        allowed: true,
        remaining: RATE_LIMIT_MAX,
        reset: now + RATE_LIMIT_WINDOW
      };
    }
  }

  public async trackSuspiciousActivity(ip: string, reason: string) {
    const key = `suspicious:${ip}`;
    try {
      await redis.hincrby(key, reason, 1);
      await redis.expire(key, 86400); // Keep for 24 hours

      // If too many suspicious activities, add to blocklist
      const counts = (await redis.hgetall<Record<string, number>>(key)) ?? {};
      const total = Object.values(counts).reduce((sum, count) => sum + (count ?? 0), 0);

      if (total >= 10) {
        await this.blockIP(ip, "Too many suspicious activities");
      }
    } catch (error) {
      logger.error("Failed to track suspicious activity", { error, ip, reason });
    }
  }

  public async blockIP(ip: string, reason: string) {
    try {
      await redis.set(`blocked:${ip}`, reason);
      logger.warn("IP blocked", { ip, reason });
    } catch (error) {
      logger.error("Failed to block IP", { error, ip, reason });
    }
  }

  public async isIPBlocked(ip: string): Promise<boolean> {
    try {
      return (await redis.exists(`blocked:${ip}`)) === 1;
    } catch (error) {
      logger.error("Failed to check IP block status", { error, ip });
      return false;
    }
  }

  public async enrichRequest(request: Request): Promise<SecurityContext> {
    const ip = request.headers.get("x-forwarded-for")?.split(",")[0] || "unknown";
    const userAgentString = request.headers.get("user-agent") || "";
    const path = new URL(request.url).pathname;

    // Check rate limit
    const { remaining, reset } = await this.checkRateLimit(ip, path);

    // Get geolocation and user agent info
    const geolocation = this.getGeoLocation(ip);
    const userAgent = this.getUserAgent(userAgentString);

    return {
      ip,
      userAgent,
      geolocation,
      rateLimit: {
        remaining,
        reset
      }
    };
  }
}

export const security = SecurityService.getInstance();
