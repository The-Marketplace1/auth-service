import speakeasy from "speakeasy";
import { db, usersTable } from "../repositories/database";
import { eq } from "drizzle-orm";

export async function setup2FA(userId: string, email: string) {
  const secret = speakeasy.generateSecret({
    name: `Marketplace:${email}`,
    length: 20,
  });

  await db
    .update(usersTable)
    .set({ twoFactorSecret: secret.base32 })
    .where(eq(usersTable.id, userId));

  const qrCodeUrl = `https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=${encodeURIComponent(secret.otpauth_url ?? "")}`;

  return {
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url ?? "",
    qrCodeUrl,
  };
}

export async function verify2FA(userId: string, totpCode: string) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  if (!user || !user.twoFactorSecret) {
    throw Object.assign(new Error("2FA not initialized"), { status: 400 });
  }

  const valid = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: "base32",
    token: totpCode,
    window: 1,
  });

  if (!valid) {
    throw Object.assign(new Error("Invalid TOTP code"), { status: 400 });
  }

  await db
    .update(usersTable)
    .set({ twoFactorEnabled: true })
    .where(eq(usersTable.id, userId));

  return { message: "2FA enabled successfully" };
}

export async function disable2FA(userId: string, totpCode: string) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  if (!user || !user.twoFactorSecret) {
    throw Object.assign(new Error("2FA not enabled"), { status: 400 });
  }

  const valid = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: "base32",
    token: totpCode,
    window: 1,
  });

  if (!valid) {
    throw Object.assign(new Error("Invalid TOTP code"), { status: 400 });
  }

  await db
    .update(usersTable)
    .set({ twoFactorEnabled: false, twoFactorSecret: null })
    .where(eq(usersTable.id, userId));

  return { message: "2FA disabled successfully" };
}

