import {
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify,
  randomBytes,
} from "node:crypto";
import { and, eq } from "drizzle-orm";
import bcrypt from "bcryptjs";
import { db, usersTable } from "../repositories/database";
import { config } from "../app/config";
import { getRedis } from "../utils/redis";
import {
  createAuthenticatedSession,
  type DeviceInfo,
} from "../login/auth.service";

export type OAuthProvider = "google" | "apple";

export interface OAuthIdentity {
  provider: OAuthProvider;
  providerId: string;
  email?: string;
  emailVerified: boolean;
}

type OAuthState = { provider: OAuthProvider };

const GOOGLE_TOKEN_URL =
  process.env.GOOGLE_TOKEN_URL ?? "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL =
  process.env.GOOGLE_USERINFO_URL ??
  "https://openidconnect.googleapis.com/v1/userinfo";
const APPLE_TOKEN_URL =
  process.env.APPLE_TOKEN_URL ?? "https://appleid.apple.com/auth/token";
const APPLE_JWKS_URL =
  process.env.APPLE_JWKS_URL ?? "https://appleid.apple.com/auth/keys";

function oauthError(message: string, status = 400): Error & { status: number } {
  return Object.assign(new Error(message), { status });
}

function providerNotConfigured(provider: OAuthProvider): never {
  throw oauthError(
    `${provider[0].toUpperCase()}${provider.slice(1)} OAuth is not configured.`,
    503,
  );
}

export function getOAuthRedirectUri(provider: OAuthProvider): string {
  const configured =
    provider === "google"
      ? process.env.GOOGLE_REDIRECT_URI
      : process.env.APPLE_REDIRECT_URI;
  const baseUrl = process.env.API_BASE_URL;
  const fallback = baseUrl
    ? `${baseUrl}/api/auth/oauth/${provider}/callback`
    : null;
  if (!configured && !fallback) {
    providerNotConfigured(provider);
  }
  return configured ?? fallback!;
}

function stateKey(state: string): string {
  return `oauth:state:${state}`;
}

export async function createOAuthState(
  provider: OAuthProvider,
): Promise<string> {
  const state = randomBytes(32).toString("base64url");
  const redis = await getRedis();
  await redis.set(
    stateKey(state),
    JSON.stringify({ provider } satisfies OAuthState),
    "EX",
    config.oauthStateTtlSeconds,
  );
  return state;
}

/**
 * GETDEL makes a callback state single-use even when two callback requests
 * arrive concurrently. This is deliberately consumed before exchanging the
 * authorization code so replay cannot repeat a provider request.
 */
export async function consumeOAuthState(
  state: unknown,
  provider: OAuthProvider,
): Promise<void> {
  if (typeof state !== "string" || state.length < 20 || state.length > 200) {
    throw oauthError("Invalid or expired OAuth state");
  }
  const redis = await getRedis();
  const stored = await redis.getdel(stateKey(state));
  if (!stored) throw oauthError("Invalid or expired OAuth state");
  try {
    const parsed = JSON.parse(stored) as OAuthState;
    if (parsed.provider !== provider) {
      throw oauthError("Invalid OAuth state");
    }
  } catch (err) {
    if ((err as { status?: number }).status) throw err;
    throw oauthError("Invalid or expired OAuth state");
  }
}

function requiredEnv(
  provider: OAuthProvider,
  value: string | undefined,
): string {
  if (!value) providerNotConfigured(provider);
  return value;
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  try {
    const body = (await response.json()) as unknown;
    if (body && typeof body === "object") {
      return body as Record<string, unknown>;
    }
  } catch {
    // Provider response details are intentionally not exposed to callers.
  }
  throw oauthError("OAuth provider returned an invalid response", 502);
}

function providerExchangeError(provider: OAuthProvider): Error & {
  status: number;
} {
  return oauthError(
    `${provider[0].toUpperCase()}${provider.slice(1)} sign-in could not be completed.`,
    502,
  );
}

function normalizedEmail(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const email = value.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return undefined;
  return email;
}

function isVerified(value: unknown): boolean {
  return value === true || value === "true";
}

async function exchangeGoogleCode(code: string): Promise<OAuthIdentity> {
  const clientId = requiredEnv("google", process.env.GOOGLE_CLIENT_ID);
  const clientSecret = requiredEnv("google", process.env.GOOGLE_CLIENT_SECRET);

  let tokenResponse: Response;
  try {
    tokenResponse = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: getOAuthRedirectUri("google"),
        grant_type: "authorization_code",
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenResponse.ok) throw providerExchangeError("google");
    const token = await readJson(tokenResponse);
    const accessToken =
      typeof token.access_token === "string" ? token.access_token : null;
    if (!accessToken) throw providerExchangeError("google");

    const userInfoResponse = await fetch(GOOGLE_USERINFO_URL, {
      headers: { authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!userInfoResponse.ok) throw providerExchangeError("google");
    const userInfo = await readJson(userInfoResponse);
    const providerId = typeof userInfo.sub === "string" ? userInfo.sub : "";
    const email = normalizedEmail(userInfo.email);
    if (!providerId || !email || !isVerified(userInfo.email_verified)) {
      throw providerExchangeError("google");
    }
    return { provider: "google", providerId, email, emailVerified: true };
  } catch (err) {
    if ((err as { status?: number }).status) throw err;
    throw providerExchangeError("google");
  }
}

function base64urlJson(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Normalize malformed provider tokens to the public OAuth error.
  }
  throw providerExchangeError("apple");
}

function derInteger(value: Buffer): Buffer {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start += 1;
  const integer = value.subarray(start);
  return integer[0] & 0x80
    ? Buffer.concat([Buffer.from([0]), integer])
    : integer;
}

function joseSignatureToDer(signature: Buffer): Buffer {
  if (signature.length !== 64) throw providerExchangeError("apple");
  const r = derInteger(signature.subarray(0, 32));
  const s = derInteger(signature.subarray(32));
  const body = Buffer.concat([
    Buffer.from([0x02, r.length]),
    r,
    Buffer.from([0x02, s.length]),
    s,
  ]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

async function verifyAppleIdToken(token: string): Promise<OAuthIdentity> {
  const parts = token.split(".");
  if (parts.length !== 3) throw providerExchangeError("apple");
  const header = base64urlJson(parts[0]);
  const claims = base64urlJson(parts[1]);
  if (header.alg !== "ES256" || typeof header.kid !== "string") {
    throw providerExchangeError("apple");
  }

  const issuer = claims.iss;
  const audience = claims.aud;
  const expiresAt = claims.exp;
  const providerId = typeof claims.sub === "string" ? claims.sub : "";
  const clientId = requiredEnv("apple", process.env.APPLE_CLIENT_ID);
  const validAudience =
    audience === clientId ||
    (Array.isArray(audience) && audience.includes(clientId));
  if (
    issuer !== "https://appleid.apple.com" ||
    !validAudience ||
    typeof expiresAt !== "number" ||
    expiresAt <= Math.floor(Date.now() / 1000) ||
    !providerId
  ) {
    throw providerExchangeError("apple");
  }

  let keysResponse: Response;
  try {
    keysResponse = await fetch(APPLE_JWKS_URL, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!keysResponse.ok) throw providerExchangeError("apple");
    const jwks = await readJson(keysResponse);
    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
    const key = keys.find(
      (candidate) =>
        candidate &&
        typeof candidate === "object" &&
        (candidate as { kid?: unknown }).kid === header.kid,
    ) as { kty?: string; crv?: string; x?: string; y?: string } | undefined;
    if (
      !key ||
      key.kty !== "EC" ||
      key.crv !== "P-256" ||
      typeof key.x !== "string" ||
      typeof key.y !== "string"
    ) {
      throw providerExchangeError("apple");
    }
    const verifier = createVerify("SHA256");
    verifier.update(`${parts[0]}.${parts[1]}`);
    verifier.end();
    const validSignature = verifier.verify(
      createPublicKey({
        key: {
          kty: "EC",
          crv: "P-256",
          x: key.x,
          y: key.y,
        },
        format: "jwk",
      }),
      joseSignatureToDer(Buffer.from(parts[2], "base64url")),
    );
    if (!validSignature) throw providerExchangeError("apple");
  } catch (err) {
    if ((err as { status?: number }).status) throw err;
    throw providerExchangeError("apple");
  }

  const email = normalizedEmail(claims.email);
  if (
    claims.email !== undefined &&
    (!email || !isVerified(claims.email_verified))
  ) {
    throw providerExchangeError("apple");
  }
  return {
    provider: "apple",
    providerId,
    email,
    emailVerified: Boolean(email),
  };
}

function appleClientSecret(): string {
  const teamId = requiredEnv("apple", process.env.APPLE_TEAM_ID);
  const keyId = requiredEnv("apple", process.env.APPLE_KEY_ID);
  const privateKeyValue = requiredEnv(
    "apple",
    process.env.APPLE_PRIVATE_KEY,
  ).replace(/\\n/g, "\n");
  const now = Math.floor(Date.now() / 1000);
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({ alg: "ES256", kid: keyId, typ: "JWT" });
  const payload = encode({
    iss: teamId,
    iat: now,
    exp: now + 5 * 60,
    aud: "https://appleid.apple.com",
    sub: process.env.APPLE_CLIENT_ID,
  });
  const signer = createSign("SHA256");
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign({
    key: createPrivateKey(privateKeyValue),
    dsaEncoding: "ieee-p1363",
  });
  if (signature.length !== 64) throw providerExchangeError("apple");
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

async function exchangeAppleCode(code: string): Promise<OAuthIdentity> {
  try {
    const clientId = requiredEnv("apple", process.env.APPLE_CLIENT_ID);
    const secret = appleClientSecret();
    const response = await fetch(APPLE_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: secret,
        code,
        grant_type: "authorization_code",
        redirect_uri: getOAuthRedirectUri("apple"),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw providerExchangeError("apple");
    const token = await readJson(response);
    if (typeof token.id_token !== "string") {
      throw providerExchangeError("apple");
    }
    return verifyAppleIdToken(token.id_token);
  } catch (err) {
    if ((err as { status?: number }).status) throw err;
    throw providerExchangeError("apple");
  }
}

export async function exchangeAuthorizationCode(
  provider: OAuthProvider,
  code: string,
): Promise<OAuthIdentity> {
  if (typeof code !== "string" || code.length === 0 || code.length > 4096) {
    throw oauthError("Authorization code is required");
  }
  return provider === "google"
    ? exchangeGoogleCode(code)
    : exchangeAppleCode(code);
}

export async function loginWithOAuth(
  identity: OAuthIdentity,
  device?: DeviceInfo,
) {
  const providerMatch = await db
    .select()
    .from(usersTable)
    .where(
      and(
        eq(usersTable.oauthProvider, identity.provider),
        eq(usersTable.oauthProviderId, identity.providerId),
      ),
    )
    .limit(1);
  let user = providerMatch[0];
  if (user?.role === "admin") {
    throw oauthError("Admin accounts must use password sign-in.", 403);
  }

  if (!user && identity.email) {
    const emailMatch = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.email, identity.email))
      .limit(1);
    const existing = emailMatch[0];
    if (existing) {
      if (existing.role === "admin") {
        throw oauthError("Admin accounts must use password sign-in.", 403);
      }
      if (
        existing.oauthProvider &&
        (existing.oauthProvider !== identity.provider ||
          existing.oauthProviderId !== identity.providerId)
      ) {
        throw oauthError("An account already exists for this email", 409);
      }
      const updated = await db
        .update(usersTable)
        .set({
          oauthProvider: identity.provider,
          oauthProviderId: identity.providerId,
          emailVerifiedAt: identity.emailVerified
            ? (existing.emailVerifiedAt ?? new Date())
            : existing.emailVerifiedAt,
        })
        .where(eq(usersTable.id, existing.id))
        .returning();
      user = updated[0];
    }
  }

  if (!user) {
    if (!identity.email || !identity.emailVerified) {
      throw oauthError("The OAuth account does not have a verified email");
    }
    const password = await bcrypt.hash(
      `oauth:${randomBytes(32).toString("base64url")}`,
      config.bcryptSaltRounds,
    );
    const created = await db
      .insert(usersTable)
      .values({
        email: identity.email,
        password,
        role: "customer",
        emailVerifiedAt: new Date(),
        oauthProvider: identity.provider,
        oauthProviderId: identity.providerId,
      })
      .returning();
    user = created[0];
  }

  if (!user) throw oauthError("Unable to create OAuth account", 500);
  return createAuthenticatedSession(user, device, {
    metadata: { provider: identity.provider },
  });
}
