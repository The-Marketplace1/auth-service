const nodeEnv = process.env.NODE_ENV ?? "development";
const jwtAccessSecret = process.env.JWT_ACCESS_SECRET;
const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
const redisUrl = process.env.REDIS_URL ?? null;

if (!jwtAccessSecret || !jwtRefreshSecret) {
  throw new Error(
    "JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be configured",
  );
}

if (nodeEnv === "production" && !redisUrl) {
  throw new Error("REDIS_URL must be configured in production");
}

export const config = {
  // ── JWT ─────────────────────────────────────────────────────────────────────
  jwtAccessSecret,
  jwtRefreshSecret,
  jwtAccessExpiresIn: "15m",
  jwtRefreshExpiresIn: "7d",
  jwtAccessExpiresInSeconds: 15 * 60,
  jwtRefreshExpiresInSeconds: 7 * 24 * 60 * 60,

  // ── Passwords ────────────────────────────────────────────────────────────────
  bcryptSaltRounds: 12,

  // ── Redis ────────────────────────────────────────────────────────────────────
  redisUrl,
  verificationTtlSeconds: 24 * 60 * 60,
  passwordResetTtlSeconds: 60 * 60,
  phoneVerificationTtlSeconds: 10 * 60,
  oauthStateTtlSeconds: 10 * 60,
  eventSinkUrl: process.env.AUTH_EVENT_SINK_URL ?? null,

  // ── Account lockout ──────────────────────────────────────────────────────────
  loginMaxAttempts: 5, // failed attempts before lock
  loginLockWindowSeconds: 15 * 60, // 15-minute lockout window
  loginLockTtlSeconds: 15 * 60, // how long the lock lasts

  // ── Environment ──────────────────────────────────────────────────────────────
  nodeEnv,
  corsOrigins: (process.env.CORS_ORIGINS ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
};

if (config.nodeEnv === "production" && config.corsOrigins.length === 0) {
  throw new Error(
    "JWT secrets and at least one CORS origin must be configured in production",
  );
}

if (
  config.nodeEnv === "production" &&
  config.eventSinkUrl &&
  !config.eventSinkUrl.startsWith("https://")
) {
  throw new Error("AUTH_EVENT_SINK_URL must use HTTPS in production");
}

