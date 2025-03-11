import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import * as schema from "./schema";

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is not set");
}

// Create the Neon SQL instance
const sql = neon(process.env.DATABASE_URL);

// Create the database instance
export const db = drizzle(sql, { schema });

// Retry logic for queries
const withRetry = async <T>(fn: () => Promise<T>, retries = 3): Promise<T> => {
  try {
    return await fn();
  } catch (error) {
    if (retries > 0 && error instanceof Error) {
      const isConnectionError =
        error.message.includes("connection") ||
        error.message.includes("timeout") ||
        error.message.includes("terminated");

      if (isConnectionError) {
        console.warn(`Database operation failed, retrying... (${retries} attempts left)`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
        return withRetry(fn, retries - 1);
      }
    }
    throw error;
  }
};
