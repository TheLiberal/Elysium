import { TriggerClient } from "@trigger.dev/sdk";
import * as dotenv from "dotenv";

dotenv.config();

export const client = new TriggerClient({
  id: "elysium",
  apiKey: process.env.TRIGGER_API_KEY,
  apiUrl: process.env.TRIGGER_API_URL
});
