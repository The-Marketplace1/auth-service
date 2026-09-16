import { createHash, randomBytes, randomInt } from "crypto";
import { db, usersTable } from "../repositories/database";
import { eq } from "drizzle-orm";
import { config } from "../app/config";
import { getRedis } from "../utils/redis";
import { emitAuthEvent } from "../events/events.service";

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function emailKey(token: string): string {
  return `auth:verify-email:${digest(token)}`;
}

function phoneKey(userId: string): string {
  return `auth:verify-phone:${userId}`;
}

export async function createEmailVerificationChallenge(
  userId: string,
  email: string,
  context: { ipAddress?: string | null; userAgent?: string | null } = {},
): Promise<string> {
  const token = randomBytes(32).toString("hex");
  const redis = await getRedis();
  await redis.set(emailKey(token), userId, "EX", config.verificationTtlSeconds);
  await emitAuthEvent("verification.requested", {
    userId,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
    metadata: {
      channel: "email",
      emailDomain: email.split("@")[1] ?? "unknown",
    },
    delivery: {
      channel: "email",
      recipient: email,
      token,
      expiresIn: config.verificationTtlSeconds,
    },
  });
  return token;
}

export async function verifyEmail(token: string): Promise<void> {
  const redis = await getRedis();
  const userId = await redis.get(emailKey(token));
  if (!userId) {
    throw Object.assign(new Error("Verification token is invalid or expired"), {
      status: 400,
    });
  }

  const [user] = await db
    .select({ id: usersTable.id, emailVerifiedAt: usersTable.emailVerifiedAt })
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  if (!user) {
    await redis.del(emailKey(token));
    throw Object.assign(new Error("Verification token is invalid or expired"), {
      status: 400,
    });
  }

  await redis.del(emailKey(token));
  if (!user.emailVerifiedAt) {
    await db
      .update(usersTable)
      .set({ emailVerifiedAt: new Date() })
      .where(eq(usersTable.id, userId));
    await emitAuthEvent("user.verified", {
      userId,
      metadata: { channel: "email" },
    });
  }
}

export async function requestPhoneVerification(
  userId: string,
  phone: string,
  context: { ipAddress?: string | null; userAgent?: string | null } = {},
): Promise<void> {
  const code = randomInt(100000, 1_000_000).toString();
  const redis = await getRedis();
  await redis.set(
    phoneKey(userId),
    JSON.stringify({ phone, codeHash: digest(code) }),
    "EX",
    config.phoneVerificationTtlSeconds,
  );
  await emitAuthEvent("phone_verification.requested", {
    userId,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
    metadata: { channel: "phone" },
    delivery: {
      channel: "phone",
      recipient: phone,
      code,
      expiresIn: config.phoneVerificationTtlSeconds,
    },
  });
}

export async function verifyPhone(userId: string, code: string): Promise<void> {
  const redis = await getRedis();
  const raw = await redis.get(phoneKey(userId));
  if (!raw) {
    throw Object.assign(
      new Error("Phone verification code is invalid or expired"),
      { status: 400 },
    );
  }

  let challenge: { phone: string; codeHash: string };
  try {
    challenge = JSON.parse(raw) as { phone: string; codeHash: string };
  } catch {
    await redis.del(phoneKey(userId));
    throw Object.assign(
      new Error("Phone verification code is invalid or expired"),
      { status: 400 },
    );
  }
  if (digest(code) !== challenge.codeHash) {
    throw Object.assign(
      new Error("Phone verification code is invalid or expired"),
      { status: 400 },
    );
  }

  const [existingPhone] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.phone, challenge.phone))
    .limit(1);
  if (existingPhone && existingPhone.id !== userId) {
    throw Object.assign(
      new Error("Phone number is already verified on another account"),
      { status: 409 },
    );
  }

  await redis.del(phoneKey(userId));
  await db
    .update(usersTable)
    .set({ phone: challenge.phone, phoneVerifiedAt: new Date() })
    .where(eq(usersTable.id, userId));
  await emitAuthEvent("user.verified", {
    userId,
    metadata: { channel: "phone" },
  });
}

