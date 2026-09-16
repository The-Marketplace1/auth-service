import bcrypt from "bcryptjs";
import { randomUUID } from "crypto";
import { db, usersTable } from "../repositories/database";
import { eq } from "drizzle-orm";
import { config } from "../app/config";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "../tokens/jwt";
import { getRedis } from "../utils/redis";
import { logger } from "../utils/logger";
import {
  createSession,
  getStoredRefreshToken,
  rotateRefreshToken,
  revokeSession,
  revokeAllSessions,
  getActiveSessions,
} from "../sessions/session.service";
import { emitAuthEvent } from "../events/events.service";
import { createEmailVerificationChallenge } from "../verification/verification.service";
import { consumePasswordResetToken } from "../recovery/password-recovery.service";
import { assertStrongPassword } from "../credentials/password-policy";
import type { ProfessionalDetails, User } from "../repositories/database";

export { revokeAllSessions, getActiveSessions };

// ── Redis key helpers ─────────────────────────────────────────────────────────

/** Counts failed login attempts for an email address. */
function attemptsKey(email: string): string {
  return `auth:fail:${email}`;
}

/** Set when an account is locked out after too many failures. */
function lockKey(email: string): string {
  return `auth:lock:${email}`;
}

// ── Lockout helpers ───────────────────────────────────────────────────────────

async function assertNotLocked(email: string): Promise<void> {
  const redis = await getRedis();
  const locked = await redis.get(lockKey(email));
  if (locked) {
    const ttl = await redis.ttl(lockKey(email));
    throw Object.assign(
      new Error(
        `Account locked due to too many failed attempts. Try again in ${Math.ceil(ttl / 60)} minute(s).`,
      ),
      { status: 429 },
    );
  }
}

async function recordFailedAttempt(email: string): Promise<void> {
  const redis = await getRedis();
  const attempts = await redis.incr(attemptsKey(email));
  if (attempts === 1) {
    await redis.expire(attemptsKey(email), config.loginLockWindowSeconds);
  }
  logger.warn({ attempts }, "Failed login attempt");
  if (attempts >= config.loginMaxAttempts) {
    await redis.set(lockKey(email), "1", "EX", config.loginLockTtlSeconds);
    await redis.del(attemptsKey(email));
    logger.warn("Account locked after too many failed attempts");
    throw Object.assign(
      new Error(
        `Account locked after ${config.loginMaxAttempts} failed attempts. Try again in ${config.loginLockTtlSeconds / 60} minutes.`,
      ),
      { status: 429 },
    );
  }
}

async function clearFailedAttempts(email: string): Promise<void> {
  const redis = await getRedis();
  await redis.del(attemptsKey(email));
  await redis.del(lockKey(email));
}

// ── Device info ───────────────────────────────────────────────────────────────

export interface DeviceInfo {
  userAgent?: string | null;
  ipAddress?: string | null;
}

export async function createAuthenticatedSession(
  user: User,
  device?: DeviceInfo,
  options: { metadata?: Record<string, unknown> } = {},
) {
  const sessionId = randomUUID();
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    sessionId,
  });
  const refreshToken = signRefreshToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    sessionId,
  });

  await createSession(user.id, sessionId, refreshToken, {
    userAgent: device?.userAgent,
    ipAddress: device?.ipAddress,
  });
  await emitAuthEvent("user.login", {
    userId: user.id,
    sessionId,
    ipAddress: device?.ipAddress,
    userAgent: device?.userAgent,
    metadata: options.metadata,
  });
  await emitAuthEvent("session.created", {
    userId: user.id,
    sessionId,
    ipAddress: device?.ipAddress,
    userAgent: device?.userAgent,
  });

  logger.info(
    { userId: user.id, role: user.role, sessionId },
    "User logged in",
  );
  return { accessToken, refreshToken, user, sessionId };
}

// ── Auth functions ────────────────────────────────────────────────────────────

export async function registerUser(
  email: string,
  password: string,
  role?: "customer" | "professional",
  professionalDetails?: ProfessionalDetails | null,
  device?: DeviceInfo,
) {
  const existing = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existing.length > 0) {
    throw Object.assign(new Error("Email already registered"), { status: 409 });
  }

  assertStrongPassword(password);
  const hashed = await bcrypt.hash(password, config.bcryptSaltRounds);
  const [user] = await db
    .insert(usersTable)
    .values({
      email,
      password: hashed,
      role: role ?? "customer",
      professionalDetails:
        role === "professional" ? (professionalDetails ?? null) : null,
    })
    .returning();

  // Generate sessionId upfront so it can be embedded in both tokens
  const sessionId = randomUUID();
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    sessionId,
  });
  const refreshToken = signRefreshToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    sessionId,
  });

  await createSession(user.id, sessionId, refreshToken, {
    userAgent: device?.userAgent,
    ipAddress: device?.ipAddress,
  });
  await emitAuthEvent("user.created", {
    userId: user.id,
    sessionId,
    ipAddress: device?.ipAddress,
    userAgent: device?.userAgent,
    metadata: { role: user.role },
  });
  await emitAuthEvent("session.created", {
    userId: user.id,
    sessionId,
    ipAddress: device?.ipAddress,
    userAgent: device?.userAgent,
  });
  await createEmailVerificationChallenge(user.id, user.email, device);

  logger.info(
    { userId: user.id, role: user.role, sessionId },
    "User registered",
  );
  return { accessToken, refreshToken, user, sessionId };
}

export async function loginUser(
  email: string,
  password: string,
  totpCode?: string | null,
  device?: DeviceInfo,
) {
  // ── 1. Lockout check ──────────────────────────────────────────────────────
  await assertNotLocked(email);

  // ── 2. Fetch user ─────────────────────────────────────────────────────────
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (!user) {
    await recordFailedAttempt(email);
    throw Object.assign(new Error("Invalid credentials"), { status: 401 });
  }

  // ── 3. Password check ─────────────────────────────────────────────────────
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    await recordFailedAttempt(email);
    throw Object.assign(new Error("Invalid credentials"), { status: 401 });
  }

  // ── 4. 2FA check ──────────────────────────────────────────────────────────
  if (user.twoFactorEnabled && user.twoFactorSecret) {
    if (!totpCode) {
      throw Object.assign(new Error("2FA code required"), { status: 401 });
    }
    const speakeasy = await import("speakeasy");
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token: totpCode,
      window: 1,
    });
    if (!verified) {
      await recordFailedAttempt(email);
      throw Object.assign(new Error("Invalid 2FA code"), { status: 401 });
    }
  }

  // ── 5. Success — clear lockout counters ───────────────────────────────────
  await clearFailedAttempts(email);

  // ── 6. Create session and issue tokens ────────────────────────────────────
  return createAuthenticatedSession(user, device, {
    metadata: { role: user.role },
  });
}

export async function logoutUser(
  refreshToken: string,
  expectedUserId?: string,
): Promise<void> {
  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    throw Object.assign(new Error("Invalid refresh token"), { status: 401 });
  }
  if (expectedUserId && payload.sub !== expectedUserId) {
    throw Object.assign(
      new Error("Refresh token does not belong to the current user"),
      { status: 403 },
    );
  }
  await revokeSession(payload.sub, payload.sessionId);
  await emitAuthEvent("user.logout", {
    userId: payload.sub,
    sessionId: payload.sessionId,
  });
}

export async function logoutAllDevices(userId: string): Promise<number> {
  return revokeAllSessions(userId);
}

export async function refreshAccessToken(refreshToken: string): Promise<{
  accessToken: string;
  refreshToken: string;
}> {
  // ── 1. Verify signature + expiry ──────────────────────────────────────────
  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    throw Object.assign(new Error("Invalid or expired refresh token"), {
      status: 401,
    });
  }

  const { sub: userId, sessionId } = payload;

  // ── 2. Check token matches what's stored for this session ─────────────────
  const stored = await getStoredRefreshToken(userId, sessionId);
  if (!stored || stored !== refreshToken) {
    throw Object.assign(new Error("Refresh token revoked or not found"), {
      status: 401,
    });
  }

  // ── 3. Fetch fresh user data (role may have changed) ──────────────────────
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);

  if (!user) {
    throw Object.assign(new Error("User not found"), { status: 401 });
  }

  // ── 4. ROTATE: issue new tokens, invalidate old — session continues ────────
  const newAccessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    sessionId,
  });
  const newRefreshToken = signRefreshToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    sessionId,
  });

  await rotateRefreshToken(user.id, sessionId, newRefreshToken);

  logger.info({ userId: user.id, sessionId }, "Token rotated");
  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
}

export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  assertStrongPassword(newPassword);
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
    throw Object.assign(new Error("Current password is incorrect"), {
      status: 401,
    });
  }
  if (await bcrypt.compare(newPassword, user.password)) {
    throw Object.assign(
      new Error("New password must be different from the current password"),
      { status: 400 },
    );
  }

  await db
    .update(usersTable)
    .set({ password: await bcrypt.hash(newPassword, config.bcryptSaltRounds) })
    .where(eq(usersTable.id, userId));
  await revokeAllSessions(userId);
  await emitAuthEvent("user.password_changed", { userId });
}

export async function resetPassword(
  userId: string,
  newPassword: string,
): Promise<void> {
  assertStrongPassword(newPassword);
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  if (!user) {
    throw Object.assign(
      new Error("Password reset token is invalid or expired"),
      { status: 400 },
    );
  }
  if (await bcrypt.compare(newPassword, user.password)) {
    throw Object.assign(
      new Error("New password must be different from the current password"),
      { status: 400 },
    );
  }

  await db
    .update(usersTable)
    .set({ password: await bcrypt.hash(newPassword, config.bcryptSaltRounds) })
    .where(eq(usersTable.id, userId));
  await revokeAllSessions(userId);
  await emitAuthEvent("user.password_reset", { userId });
}

export async function resetPasswordWithToken(
  token: string,
  newPassword: string,
): Promise<void> {
  const userId = await consumePasswordResetToken(token);
  await resetPassword(userId, newPassword);
}

