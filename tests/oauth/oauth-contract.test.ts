import assert from "node:assert/strict";
import test from "node:test";
import { createPrivateKey, createSign, generateKeyPairSync } from "node:crypto";

process.env.DATABASE_URL ??= "postgres://postgres:postgres@127.0.0.1:5432/test";
process.env.API_BASE_URL ??= "http://127.0.0.1:8080";
process.env.GOOGLE_CLIENT_ID = "google-client";
process.env.GOOGLE_CLIENT_SECRET = "google-secret";
process.env.GOOGLE_REDIRECT_URI =
  "http://127.0.0.1:8080/api/auth/oauth/google/callback";
process.env.APPLE_CLIENT_ID = "com.marketplace.web";
process.env.APPLE_TEAM_ID = "apple-team";
process.env.APPLE_KEY_ID = "apple-key";
process.env.APPLE_REDIRECT_URI =
  "http://127.0.0.1:8080/api/auth/oauth/apple/callback";

const oauth = await import("../../src/oauth/oauth.service");
const originalFetch = globalThis.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function signedAppleIdToken(): { token: string; jwk: Record<string, unknown> } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  process.env.APPLE_PRIVATE_KEY = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({ alg: "ES256", kid: "apple-key", typ: "JWT" });
  const payload = encode({
    iss: "https://appleid.apple.com",
    aud: "com.marketplace.web",
    sub: "apple-user-123",
    email: "Apple.User@Example.com",
    email_verified: true,
    exp: Math.floor(Date.now() / 1000) + 300,
  });
  const signer = createSign("SHA256");
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign({
    key: createPrivateKey(process.env.APPLE_PRIVATE_KEY),
    dsaEncoding: "ieee-p1363",
  });
  return {
    token: `${header}.${payload}.${signature.toString("base64url")}`,
    jwk: { ...jwk, kid: "apple-key", alg: "ES256", use: "sig" },
  };
}

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("OAuth state is single-use and provider-bound", async () => {
  const state = await oauth.createOAuthState("google");
  await oauth.consumeOAuthState(state, "google");
  await assert.rejects(
    () => oauth.consumeOAuthState(state, "google"),
    (error: unknown) =>
      (error as { status?: number }).status === 400 &&
      /invalid or expired/i.test((error as Error).message),
  );

  const appleState = await oauth.createOAuthState("apple");
  await assert.rejects(
    () => oauth.consumeOAuthState(appleState, "google"),
    (error: unknown) =>
      (error as { status?: number }).status === 400 &&
      /invalid oauth state/i.test((error as Error).message),
  );
  await assert.rejects(() => oauth.consumeOAuthState(appleState, "apple"));
});

test("Google exchanges the code and uses verified userinfo identity", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    calls.push({ url, init });
    if (url === "https://oauth2.googleapis.com/token") {
      return jsonResponse({ access_token: "google-access-token" });
    }
    return jsonResponse({
      sub: "google-user-123",
      email: "Google.User@Example.com",
      email_verified: true,
    });
  }) as typeof fetch;

  const identity = await oauth.exchangeAuthorizationCode(
    "google",
    "google-authorization-code",
  );
  assert.deepEqual(identity, {
    provider: "google",
    providerId: "google-user-123",
    email: "google.user@example.com",
    emailVerified: true,
  });
  assert.equal(calls.length, 2);
  assert.match(String(calls[0].init?.body), /code=google-authorization-code/);
  assert.doesNotMatch(
    JSON.stringify(identity),
    /access-token|authorization-code/,
  );
});

test("Apple exchanges the code and validates the signed identity token", async () => {
  const appleToken = signedAppleIdToken();
  globalThis.fetch = (async (input) => {
    const url = String(input);
    if (url === "https://appleid.apple.com/auth/token") {
      return jsonResponse({ id_token: appleToken.token });
    }
    return jsonResponse({ keys: [appleToken.jwk] });
  }) as typeof fetch;

  const identity = await oauth.exchangeAuthorizationCode(
    "apple",
    "apple-authorization-code",
  );
  assert.deepEqual(identity, {
    provider: "apple",
    providerId: "apple-user-123",
    email: "apple.user@example.com",
    emailVerified: true,
  });
});

test("provider failures use a safe error without code or token details", async () => {
  globalThis.fetch = (async () =>
    jsonResponse(
      {
        error: "invalid_grant",
        error_description: "authorization code is invalid",
        access_token: "provider-secret",
      },
      400,
    )) as typeof fetch;

  await assert.rejects(
    () => oauth.exchangeAuthorizationCode("google", "sensitive-code"),
    (error: unknown) => {
      const message = (error as Error).message;
      return (
        (error as { status?: number }).status === 502 &&
        !message.includes("sensitive-code") &&
        !message.includes("provider-secret") &&
        /could not be completed/i.test(message)
      );
    },
  );
});

