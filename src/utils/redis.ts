import { logger } from "./logger";
import { config } from "../app/config";

export interface RedisLike {
  set(
    key: string,
    value: string,
    exArg: "EX",
    seconds: number,
  ): Promise<unknown>;
  get(key: string): Promise<string | null>;
  getdel(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  ttl(key: string): Promise<number>;
  quit(): Promise<unknown>;
}

// ── In-memory fallback (single-process only) ──────────────────────────────────
class InMemoryRedis implements RedisLike {
  private store = new Map<
    string,
    { value: string; expiresAt: number | null }
  >();

  private alive(
    key: string,
  ): { value: string; expiresAt: number | null } | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry;
  }

  async set(
    key: string,
    value: string,
    _exArg: "EX",
    seconds: number,
  ): Promise<"OK"> {
    this.store.set(key, { value, expiresAt: Date.now() + seconds * 1000 });
    return "OK";
  }

  async get(key: string): Promise<string | null> {
    return this.alive(key)?.value ?? null;
  }

  async getdel(key: string): Promise<string | null> {
    const entry = this.alive(key);
    if (!entry) return null;
    this.store.delete(key);
    return entry.value;
  }

  async del(key: string): Promise<number> {
    return this.store.delete(key) ? 1 : 0;
  }

  async incr(key: string): Promise<number> {
    const entry = this.alive(key);
    const next = entry ? parseInt(entry.value, 10) + 1 : 1;
    this.store.set(key, {
      value: String(next),
      expiresAt: entry?.expiresAt ?? null,
    });
    return next;
  }

  async expire(key: string, seconds: number): Promise<1 | 0> {
    const entry = this.store.get(key);
    if (!entry) return 0;
    this.store.set(key, {
      value: entry.value,
      expiresAt: Date.now() + seconds * 1000,
    });
    return 1;
  }

  async ttl(key: string): Promise<number> {
    const entry = this.alive(key);
    if (!entry) return -2;
    if (entry.expiresAt === null) return -1;
    return Math.max(0, Math.ceil((entry.expiresAt - Date.now()) / 1000));
  }

  async quit(): Promise<"OK"> {
    return "OK";
  }
}

// ── Singleton ─────────────────────────────────────────────────────────────────
let redisClient: RedisLike | null = null;

export async function getRedis(): Promise<RedisLike> {
  if (redisClient) return redisClient;

  if (config.redisUrl) {
    try {
      const { default: Redis } = await import("ioredis");
      const client = new Redis(config.redisUrl, {
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        lazyConnect: false,
      });

      await new Promise<void>((resolve, reject) => {
        client.once("ready", resolve);
        client.once("error", reject);
        setTimeout(() => reject(new Error("Redis connect timeout")), 5000);
      });

      client.on("error", (err: Error) => {
        logger.error({ err }, "Redis client error");
      });

      logger.info(
        { host: new URL(config.redisUrl!).hostname },
        "Connected to Redis",
      );
      redisClient = client as unknown as RedisLike;
    } catch (err) {
      if (config.nodeEnv === "production") {
        throw new Error("Redis connection failed in production", {
          cause: err,
        });
      }
      logger.warn(
        { err },
        "Redis connection failed — falling back to in-memory store",
      );
      redisClient = new InMemoryRedis();
    }
  } else {
    if (config.nodeEnv === "production") {
      throw new Error("REDIS_URL must be configured in production");
    }
    logger.warn(
      "REDIS_URL not set — using in-memory token store (not suitable for multi-instance production)",
    );
    redisClient = new InMemoryRedis();
  }

  return redisClient;
}

/** Force a new connection (useful for testing) */
export function resetRedis(): void {
  redisClient = null;
}

