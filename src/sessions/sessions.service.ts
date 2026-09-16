import { db, sessionsTable } from "../repositories/database";
import { eq, and, desc } from "drizzle-orm";
import type { Session } from "../repositories/database";
import { getRedis } from "../utils/redis";
import { logger } from "../utils/logger";
import { config } from "../app/config";
import { emitAuthEvent } from "../events/events.service";

export type { Session };

// ── Redis key ─────────────────────────────────────────────────────────────────

/** refresh:{userId}:{sessionId} */
export function sessionRefreshKey(userId: string, sessionId: string): string {
  return `refresh:${userId}:${sessionId}`;
}

// ── Session lifecycle ─────────────────────────────────────────────────────────

/**
 * Insert a new session row and store its refresh token in Redis.
 * The caller provides the sessionId (UUID) so it can be embedded in both
 * the access token and the refresh token before this call.
 */
export async function createSession(
  userId: string,
  sessionId: string,
  refreshToken: string,
  opts: { userAgent?: string | null; ipAddress?: string | null },
): Promise<void> {
  await db.insert(sessionsTable).values({
    id: sessionId,
    userId,
    userAgent: opts.userAgent ?? null,
    ipAddress: opts.ipAddress ?? null,
  });

  const redis = await getRedis();
  await redis.set(
    sessionRefreshKey(userId, sessionId),
    refreshToken,
    "EX",
    config.jwtRefreshExpiresInSeconds,
  );

  logger.info({ userId, sessionId }, "Session created");
}

/** Read the active refresh token stored for a session. */
export async function getStoredRefreshToken(
  userId: string,
  sessionId: string,
): Promise<string | null> {
  const redis = await getRedis();
  return redis.get(sessionRefreshKey(userId, sessionId));
}

/** Replace the refresh token for an existing session and bump lastActiveAt. */
export async function rotateRefreshToken(
  userId: string,
  sessionId: string,
  newToken: string,
): Promise<void> {
  const redis = await getRedis();
  await redis.set(
    sessionRefreshKey(userId, sessionId),
    newToken,
    "EX",
    config.jwtRefreshExpiresInSeconds,
  );
  await db
    .update(sessionsTable)
    .set({ lastActiveAt: new Date() })
    .where(
      and(eq(sessionsTable.id, sessionId), eq(sessionsTable.isRevoked, false)),
    );
}

/** Revoke a single session — delete its Redis key and mark the DB row revoked. */
export async function revokeSession(
  userId: string,
  sessionId: string,
): Promise<void> {
  const redis = await getRedis();
  await redis.del(sessionRefreshKey(userId, sessionId));
  await db
    .update(sessionsTable)
    .set({ isRevoked: true })
    .where(
      and(eq(sessionsTable.id, sessionId), eq(sessionsTable.userId, userId)),
    );
  await emitAuthEvent("session.revoked", { userId, sessionId });
  logger.info({ userId, sessionId }, "Session revoked");
}

/**
 * Revoke every active session for a user.
 * Queries the DB for active sessions to build Redis key list, then bulk-revokes.
 * Returns the count of sessions revoked.
 */
export async function revokeAllSessions(userId: string): Promise<number> {
  const active = await db
    .select({ id: sessionsTable.id })
    .from(sessionsTable)
    .where(
      and(eq(sessionsTable.userId, userId), eq(sessionsTable.isRevoked, false)),
    );

  if (active.length === 0) return 0;

  const redis = await getRedis();
  for (const { id: sid } of active) {
    await redis.del(sessionRefreshKey(userId, sid));
  }

  await db
    .update(sessionsTable)
    .set({ isRevoked: true })
    .where(
      and(eq(sessionsTable.userId, userId), eq(sessionsTable.isRevoked, false)),
    );

  for (const { id: sessionId } of active) {
    await emitAuthEvent("session.revoked", { userId, sessionId });
  }
  logger.info({ userId, count: active.length }, "All sessions revoked");
  return active.length;
}

/** Return active (non-revoked) sessions for a user, newest first. */
export async function getActiveSessions(userId: string): Promise<Session[]> {
  return db
    .select()
    .from(sessionsTable)
    .where(
      and(eq(sessionsTable.userId, userId), eq(sessionsTable.isRevoked, false)),
    )
    .orderBy(desc(sessionsTable.lastActiveAt));
}

/** Assert a session exists, belongs to userId, and is not revoked. */
export async function assertSessionOwned(
  userId: string,
  sessionId: string,
): Promise<void> {
  const [session] = await db
    .select({ id: sessionsTable.id, isRevoked: sessionsTable.isRevoked })
    .from(sessionsTable)
    .where(
      and(eq(sessionsTable.id, sessionId), eq(sessionsTable.userId, userId)),
    )
    .limit(1);

  if (!session) {
    throw Object.assign(new Error("Session not found"), { status: 404 });
  }
  if (session.isRevoked) {
    throw Object.assign(new Error("Session already revoked"), { status: 409 });
  }
}

