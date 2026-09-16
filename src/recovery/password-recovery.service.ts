import { createHash, randomBytes } from "node:crypto";
import { db, usersTable } from "../repositories/database";
import { eq } from "drizzle-orm";
import { config } from "../app/config";
import { getRedis } from "../utils/redis";
import { emitAuthEvent } from "../events/events.service";

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function resetKey(token: string): string {
  return `auth:password-reset:${digest(token)}`;
}

export async function requestPasswordReset(
  email: string,
  context: { ipAddress?: string | null; userAgent?: string | null } = {},
): Promise<void> {
  const [user] = await db
    .select({ id: usersTable.id, email: usersTable.email })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);
  if (!user) return;

  const token = randomBytes(32).toString("hex");
  const redis = await getRedis();
  await redis.set(
    resetKey(token),
    user.id,
    "EX",
    config.passwordResetTtlSeconds,
  );
  await emitAuthEvent("password_reset.requested", {
    userId: user.id,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
    metadata: { channel: "email" },
    delivery: {
      channel: "email",
      recipient: user.email,
      token,
      expiresIn: config.passwordResetTtlSeconds,
    },
  });
}

export async function consumePasswordResetToken(
  token: string,
): Promise<string> {
  const redis = await getRedis();
  const userId = await redis.get(resetKey(token));
  if (!userId) {
    throw Object.assign(
      new Error("Password reset token is invalid or expired"),
      { status: 400 },
    );
  }
  await redis.del(resetKey(token));
  return userId;
}

