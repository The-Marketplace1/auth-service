import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import speakeasy from "speakeasy";

const baseUrl = process.env.AUTH_BASE_URL ?? "http://127.0.0.1:8080/api";
const eventSinkUrl =
  process.env.AUTH_EVENT_SINK_INSPECT_URL ?? "http://127.0.0.1:8099/events";
const password = process.env.E2E_PASSWORD ?? "E2ePassword123";
const seedPassword = process.env.SEED_PASSWORD ?? "Password123!";

type JsonBody = Record<string, any>;

async function request(path: string, init: RequestInit = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
  const text = await response.text();
  const body = text ? (JSON.parse(text) as JsonBody) : {};
  return { response, body };
}

async function sinkEvents(): Promise<JsonBody[]> {
  const response = await fetch(eventSinkUrl);
  assert.equal(response.status, 200, "test event sink must be available");
  const body = (await response.json()) as { events?: JsonBody[] };
  return body.events ?? [];
}

async function waitForDelivery(
  type: string,
  predicate: (event: JsonBody) => boolean,
  afterCount = 0,
): Promise<JsonBody> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const events = await sinkEvents();
    const event = events
      .slice(afterCount)
      .reverse()
      .find((candidate) => {
        return (
          candidate.type === type &&
          candidate.data?.delivery &&
          predicate(candidate)
        );
      });
    if (event) return event;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.fail(`Timed out waiting for ${type} delivery event`);
}

function authHeaders(accessToken: string, origin?: string) {
  return {
    authorization: `Bearer ${accessToken}`,
    ...(origin ? { origin } : {}),
  };
}

test("Marketplace applications can complete every authentication flow", async () => {
  const suffix = randomUUID().slice(0, 8);
  const customerEmail = `customer-${suffix}@example.com`;
  const professionalEmail = `professional-${suffix}@example.com`;
  const phone = `+23480${parseInt(suffix, 16).toString().slice(-8).padStart(8, "0")}`;

  const health = await request("/healthz");
  assert.equal(health.response.status, 200);
  assert.equal(health.body.status, "ok");

  const readiness = await request("/readyz");
  assert.equal(readiness.response.status, 200);
  assert.equal(readiness.body.status, "ready");
  assert.ok(["ok", "degraded"].includes(readiness.body.dependencies.redis));

  const metrics = await fetch(`${baseUrl}/metrics`);
  assert.equal(metrics.status, 200);
  assert.match(await metrics.text(), /auth_http_requests_total/);

  const allowedCors = await fetch(`${baseUrl}/healthz`, {
    headers: { origin: "http://localhost:3000" },
  });
  assert.equal(allowedCors.status, 200);
  assert.equal(
    allowedCors.headers.get("access-control-allow-origin"),
    "http://localhost:3000",
  );

  const protectedWithoutToken: Array<[string, RequestInit]> = [
    [
      "/auth/logout",
      { method: "POST", body: JSON.stringify({ refreshToken: "x" }) },
    ],
    ["/auth/logout-all", { method: "POST" }],
    ["/auth/me", {}],
    ["/auth/sessions", {}],
    ["/auth/sessions/not-a-uuid", { method: "DELETE" }],
    ["/auth/2fa/setup", { method: "POST" }],
    [
      "/auth/2fa/verify",
      { method: "POST", body: JSON.stringify({ totpCode: "123456" }) },
    ],
    [
      "/auth/2fa/disable",
      { method: "POST", body: JSON.stringify({ totpCode: "123456" }) },
    ],
    [
      "/auth/password/change",
      {
        method: "POST",
        body: JSON.stringify({
          currentPassword: password,
          newPassword: "NewPassword123",
        }),
      },
    ],
    [
      "/auth/verify-phone/request",
      { method: "POST", body: JSON.stringify({ phone: "+2348012345678" }) },
    ],
    [
      "/auth/verify-phone",
      { method: "POST", body: JSON.stringify({ code: "123456" }) },
    ],
    ["/users", {}],
    ["/users/stats", {}],
    ["/users/not-a-user", {}],
    [
      "/users/not-a-user",
      { method: "PATCH", body: JSON.stringify({ role: "customer" }) },
    ],
    ["/users/not-a-user", { method: "DELETE" }],
  ];
  for (const [path, init] of protectedWithoutToken) {
    const unauthorized = await request(path, init);
    assert.equal(unauthorized.response.status, 401, `expected 401 for ${path}`);
    assert.equal(unauthorized.body.success, false);
    assert.equal(typeof unauthorized.body.error?.message, "string");
  }

  const incompleteProfessional = await request("/auth/register", {
    method: "POST",
    body: JSON.stringify({
      email: `incomplete-${suffix}@example.com`,
      password,
      role: "professional",
    }),
  });
  assert.equal(incompleteProfessional.response.status, 400);
  assert.equal(incompleteProfessional.body.success, false);
  assert.ok(incompleteProfessional.body.error.fields.professionalDetails);

  const customer = await request("/auth/register", {
    method: "POST",
    headers: { origin: "http://localhost:3000" },
    body: JSON.stringify({ email: customerEmail, password }),
  });
  assert.equal(customer.response.status, 201);
  assert.equal(customer.body.user.role, "customer");
  assert.equal(customer.body.user.professionalDetails, null);
  assert.equal(typeof customer.body.expiresIn, "number");
  const customerVerification = await waitForDelivery(
    "verification.requested",
    (event) => event.data.delivery.recipient === customerEmail,
  );
  assert.equal(customerVerification.data.delivery.channel, "email");

  const customerProfile = await request("/auth/me", {
    headers: authHeaders(customer.body.accessToken),
  });
  assert.equal(customerProfile.response.status, 200);
  assert.equal(customerProfile.body.email, customerEmail);

  const emailVerified = await request("/auth/verify-email", {
    method: "POST",
    body: JSON.stringify({ token: customerVerification.data.delivery.token }),
  });
  assert.equal(emailVerified.response.status, 200);
  const emailReplay = await request("/auth/verify-email", {
    method: "POST",
    body: JSON.stringify({ token: customerVerification.data.delivery.token }),
  });
  assert.equal(emailReplay.response.status, 400);

  const professional = await request("/auth/register", {
    method: "POST",
    body: JSON.stringify({
      email: professionalEmail,
      password,
      role: "professional",
      professionalDetails: {
        displayName: "E2E Professional",
        businessName: "E2E Marketplace Services",
        phone: "+2348012345678",
        serviceCategory: "Repairs",
      },
    }),
  });
  assert.equal(professional.response.status, 201);
  assert.equal(professional.body.user.role, "professional");
  assert.equal(
    professional.body.user.professionalDetails.businessName,
    "E2E Marketplace Services",
  );
  const professionalVerification = await waitForDelivery(
    "verification.requested",
    (event) => event.data.delivery.recipient === professionalEmail,
  );
  const resendEventCount = (await sinkEvents()).length;
  const resendBeforeVerification = await request("/auth/resend-verification", {
    method: "POST",
    body: JSON.stringify({ email: professionalEmail }),
  });
  assert.equal(resendBeforeVerification.response.status, 200);
  await waitForDelivery(
    "verification.requested",
    (event) => event.data.delivery.recipient === professionalEmail,
    resendEventCount,
  );
  const professionalHeaders = authHeaders(professional.body.accessToken);

  const professionalEmailVerified = await request("/auth/verify-email", {
    method: "POST",
    body: JSON.stringify({
      token: professionalVerification.data.delivery.token,
    }),
  });
  assert.equal(professionalEmailVerified.response.status, 200);

  const phoneEventCount = (await sinkEvents()).length;
  const phoneRequest = await request("/auth/verify-phone/request", {
    method: "POST",
    headers: professionalHeaders,
    body: JSON.stringify({ phone }),
  });
  assert.equal(phoneRequest.response.status, 200);
  const phoneDelivery = await waitForDelivery(
    "phone_verification.requested",
    (event) => event.data.userId === professional.body.user.id,
    phoneEventCount,
  );
  const phoneVerified = await request("/auth/verify-phone", {
    method: "POST",
    headers: professionalHeaders,
    body: JSON.stringify({ code: phoneDelivery.data.delivery.code }),
  });
  assert.equal(phoneVerified.response.status, 200);

  const professionalProfile = await request("/auth/me", {
    headers: professionalHeaders,
  });
  assert.equal(professionalProfile.response.status, 200);
  assert.equal(professionalProfile.body.phone, phone);
  assert.equal(professionalProfile.body.phoneVerifiedAt !== null, true);
  assert.equal(
    professionalProfile.body.professionalDetails.displayName,
    "E2E Professional",
  );

  const customerAccessToken = customer.body.accessToken as string;
  const customerHeaders = authHeaders(customerAccessToken);
  const initialSessions = await request("/auth/sessions", {
    headers: customerHeaders,
  });
  assert.equal(initialSessions.response.status, 200);
  assert.equal(initialSessions.body.sessions.length, 1);
  assert.equal(initialSessions.body.sessions[0].isCurrent, true);

  const secondCustomerLogin = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: customerEmail, password }),
  });
  assert.equal(secondCustomerLogin.response.status, 200);
  const twoSessions = await request("/auth/sessions", {
    headers: customerHeaders,
  });
  assert.equal(twoSessions.body.sessions.length, 2);
  const secondSession = twoSessions.body.sessions.find(
    (session: JsonBody) => !session.isCurrent,
  );
  assert.ok(secondSession?.id);

  const revokedSession = await request(`/auth/sessions/${secondSession.id}`, {
    method: "DELETE",
    headers: customerHeaders,
  });
  assert.equal(revokedSession.response.status, 200);
  const revokedSessionRefresh = await request("/auth/refresh", {
    method: "POST",
    body: JSON.stringify({
      refreshToken: secondCustomerLogin.body.refreshToken,
    }),
  });
  assert.equal(revokedSessionRefresh.response.status, 401);

  const rotated = await request("/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refreshToken: customer.body.refreshToken }),
  });
  assert.equal(rotated.response.status, 200);
  assert.notEqual(rotated.body.refreshToken, customer.body.refreshToken);
  assert.equal(typeof rotated.body.expiresIn, "number");
  const replayed = await request("/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refreshToken: customer.body.refreshToken }),
  });
  assert.equal(replayed.response.status, 401);

  const changed = await request("/auth/password/change", {
    method: "POST",
    headers: authHeaders(rotated.body.accessToken),
    body: JSON.stringify({
      currentPassword: password,
      newPassword: "ChangedPassword123",
    }),
  });
  assert.equal(changed.response.status, 200);
  const revokedAfterChange = await request("/auth/me", {
    headers: authHeaders(rotated.body.accessToken),
  });
  assert.equal(revokedAfterChange.response.status, 401);
  const changedLogin = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: customerEmail,
      password: "ChangedPassword123",
    }),
  });
  assert.equal(changedLogin.response.status, 200);
  const oldPasswordLogin = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: customerEmail, password }),
  });
  assert.equal(oldPasswordLogin.response.status, 401);

  const resetEventCount = (await sinkEvents()).length;
  const forgotKnown = await request("/auth/password/forgot", {
    method: "POST",
    body: JSON.stringify({ email: customerEmail }),
  });
  const forgotUnknown = await request("/auth/password/forgot", {
    method: "POST",
    body: JSON.stringify({ email: `unknown-${suffix}@example.com` }),
  });
  assert.equal(forgotKnown.response.status, 200);
  assert.equal(forgotUnknown.response.status, 200);
  assert.equal(forgotKnown.body.message, forgotUnknown.body.message);
  const resetDelivery = await waitForDelivery(
    "password_reset.requested",
    (event) => event.data.delivery.recipient === customerEmail,
    resetEventCount,
  );

  const reset = await request("/auth/password/reset", {
    method: "POST",
    body: JSON.stringify({
      token: resetDelivery.data.delivery.token,
      password: "ResetPassword123",
    }),
  });
  assert.equal(reset.response.status, 200);
  const resetReplay = await request("/auth/password/reset", {
    method: "POST",
    body: JSON.stringify({
      token: resetDelivery.data.delivery.token,
      password: "AnotherPassword123",
    }),
  });
  assert.equal(resetReplay.response.status, 400);
  const changedPasswordLogin = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: customerEmail,
      password: "ChangedPassword123",
    }),
  });
  assert.equal(changedPasswordLogin.response.status, 401);
  const resetLogin = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: customerEmail,
      password: "ResetPassword123",
    }),
  });
  assert.equal(resetLogin.response.status, 200);
  const logoutAll = await request("/auth/logout-all", {
    method: "POST",
    headers: authHeaders(resetLogin.body.accessToken),
  });
  assert.equal(logoutAll.response.status, 200);
  const revokedMe = await request("/auth/me", {
    headers: authHeaders(resetLogin.body.accessToken),
  });
  assert.equal(revokedMe.response.status, 401);

  const setup2fa = await request("/auth/2fa/setup", {
    method: "POST",
    headers: professionalHeaders,
  });
  assert.equal(setup2fa.response.status, 200);
  assert.ok(setup2fa.body.secret);
  assert.ok(setup2fa.body.otpauthUrl);
  const totp = () =>
    speakeasy.totp({
      secret: setup2fa.body.secret,
      encoding: "base32",
    });
  const enable2fa = await request("/auth/2fa/verify", {
    method: "POST",
    headers: professionalHeaders,
    body: JSON.stringify({ totpCode: totp() }),
  });
  assert.equal(enable2fa.response.status, 200);

  const missingTotp = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: professionalEmail, password }),
  });
  assert.equal(missingTotp.response.status, 401);
  assert.match(missingTotp.body.error.message, /2FA code required/);
  const professionalMfaLogin = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: professionalEmail,
      password,
      totpCode: totp(),
    }),
  });
  assert.equal(professionalMfaLogin.response.status, 200);
  const disable2fa = await request("/auth/2fa/disable", {
    method: "POST",
    headers: professionalHeaders,
    body: JSON.stringify({ totpCode: totp() }),
  });
  assert.equal(disable2fa.response.status, 200);
  const professionalLogout = await request("/auth/logout", {
    method: "POST",
    headers: authHeaders(professionalMfaLogin.body.accessToken),
    body: JSON.stringify({
      refreshToken: professionalMfaLogin.body.refreshToken,
    }),
  });
  assert.equal(professionalLogout.response.status, 200);
  const loggedOutRefresh = await request("/auth/refresh", {
    method: "POST",
    body: JSON.stringify({
      refreshToken: professionalMfaLogin.body.refreshToken,
    }),
  });
  assert.equal(loggedOutRefresh.response.status, 401);

  const adminSelfRegistration = await request("/auth/register", {
    method: "POST",
    body: JSON.stringify({
      email: `admin-${suffix}@example.com`,
      password,
      role: "admin",
    }),
  });
  assert.equal(adminSelfRegistration.response.status, 400);

  const adminLogin = await request("/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: "admin@marketplace.dev",
      password: seedPassword,
    }),
  });
  assert.equal(adminLogin.response.status, 200);
  assert.equal(adminLogin.body.user.role, "admin");
  const adminHeaders = authHeaders(adminLogin.body.accessToken);

  const adminStats = await request("/users/stats", {
    headers: adminHeaders,
  });
  assert.equal(adminStats.response.status, 200);
  assert.equal(typeof adminStats.body.total, "number");

  const userList = await request(
    "/users?search=" + encodeURIComponent(customerEmail),
    {
      headers: adminHeaders,
    },
  );
  assert.equal(userList.response.status, 200);
  assert.equal(userList.body.users.length, 1);
  assert.equal(userList.body.users[0].email, customerEmail);
  assert.equal(userList.body.users[0].id, customer.body.user.id);

  const userDetails = await request(`/users/${customer.body.user.id}`, {
    headers: adminHeaders,
  });
  assert.equal(userDetails.response.status, 200);
  assert.equal(userDetails.body.email, customerEmail);

  const customerStats = await request("/users/stats", {
    headers: professionalHeaders,
  });
  assert.equal(customerStats.response.status, 403);
  assert.equal(customerStats.body.success, false);

  const temporaryRole = await request(`/users/${customer.body.user.id}`, {
    method: "PATCH",
    headers: adminHeaders,
    body: JSON.stringify({ role: "professional" }),
  });
  assert.equal(temporaryRole.response.status, 200);
  assert.equal(temporaryRole.body.role, "professional");
  const restoredRole = await request(`/users/${customer.body.user.id}`, {
    method: "PATCH",
    headers: adminHeaders,
    body: JSON.stringify({ role: "customer" }),
  });
  assert.equal(restoredRole.response.status, 200);
  assert.equal(restoredRole.body.role, "customer");

  const deleted = await request(`/users/${customer.body.user.id}`, {
    method: "DELETE",
    headers: {
      authorization: `Bearer ${adminLogin.body.accessToken}`,
    },
  });
  assert.equal(deleted.response.status, 204);
  const deletedLookup = await request(`/users/${customer.body.user.id}`, {
    headers: adminHeaders,
  });
  assert.equal(deletedLookup.response.status, 404);

  const adminLogout = await request("/auth/logout", {
    method: "POST",
    headers: adminHeaders,
    body: JSON.stringify({ refreshToken: adminLogin.body.refreshToken }),
  });
  assert.equal(adminLogout.response.status, 200);
  const adminRefreshAfterLogout = await request("/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refreshToken: adminLogin.body.refreshToken }),
  });
  assert.equal(adminRefreshAfterLogout.response.status, 401);
});

test(
  "OAuth callbacks complete against the provider fixture",
  { skip: process.env.OAUTH_E2E !== "1" },
  async () => {
    async function redirectState(path: string): Promise<string> {
      const response = await fetch(`${baseUrl}${path}`, {
        redirect: "manual",
      });
      assert.equal(response.status, 302);
      const location = response.headers.get("location");
      assert.ok(location);
      const state = new URL(location).searchParams.get("state");
      assert.ok(state);
      return state;
    }

    const googleState = await redirectState("/auth/oauth/google");
    const googleSuccess = await request(
      `/auth/oauth/google/callback?code=fixture-google-code&state=${encodeURIComponent(googleState)}`,
    );
    assert.equal(googleSuccess.response.status, 200);
    assert.equal(typeof googleSuccess.body.accessToken, "string");
    assert.equal(typeof googleSuccess.body.refreshToken, "string");
    assert.equal(googleSuccess.body.user.role, "customer");

    const googleReplay = await request(
      `/auth/oauth/google/callback?code=fixture-google-code&state=${encodeURIComponent(googleState)}`,
    );
    assert.equal(googleReplay.response.status, 400);
    assert.equal(googleReplay.body.success, false);

    const googleAdminState = await redirectState("/auth/oauth/google");
    const googleAdmin = await request(
      `/auth/oauth/google/callback?code=fixture-google-admin-code&state=${encodeURIComponent(googleAdminState)}`,
    );
    assert.equal(googleAdmin.response.status, 403);
    assert.match(googleAdmin.body.error.message, /password sign-in/i);

    const cancelledGoogleState = await redirectState("/auth/oauth/google");
    const cancelledGoogle = await request(
      `/auth/oauth/google/callback?error=access_denied&state=${encodeURIComponent(cancelledGoogleState)}`,
    );
    assert.equal(cancelledGoogle.response.status, 400);
    assert.equal(cancelledGoogle.body.success, false);

    const failedGoogleState = await redirectState("/auth/oauth/google");
    const failedGoogle = await request(
      `/auth/oauth/google/callback?code=fixture-failing-code&state=${encodeURIComponent(failedGoogleState)}`,
    );
    assert.equal(failedGoogle.response.status, 502);
    assert.equal(failedGoogle.body.success, false);
    assert.doesNotMatch(
      JSON.stringify(failedGoogle.body),
      /fixture-failing-code|access-token|refresh-token/i,
    );

    const appleState = await redirectState("/auth/oauth/apple");
    const appleSuccess = await request("/auth/oauth/apple/callback", {
      method: "POST",
      body: JSON.stringify({ code: "fixture-apple-code", state: appleState }),
    });
    assert.equal(appleSuccess.response.status, 200);
    assert.equal(typeof appleSuccess.body.accessToken, "string");
    assert.equal(appleSuccess.body.user.role, "customer");

    const appleReplay = await request("/auth/oauth/apple/callback", {
      method: "POST",
      body: JSON.stringify({ code: "fixture-apple-code", state: appleState }),
    });
    assert.equal(appleReplay.response.status, 400);
    assert.equal(appleReplay.body.success, false);

    const appleAdminState = await redirectState("/auth/oauth/apple");
    const appleAdmin = await request("/auth/oauth/apple/callback", {
      method: "POST",
      body: JSON.stringify({
        code: "fixture-apple-admin-code",
        state: appleAdminState,
      }),
    });
    assert.equal(appleAdmin.response.status, 403);
    assert.match(appleAdmin.body.error.message, /password sign-in/i);

    const cancelledAppleState = await redirectState("/auth/oauth/apple");
    const cancelledApple = await request("/auth/oauth/apple/callback", {
      method: "POST",
      body: JSON.stringify({
        error: "user_cancelled_authorize",
        state: cancelledAppleState,
      }),
    });
    assert.equal(cancelledApple.response.status, 400);
    assert.equal(cancelledApple.body.success, false);

    const failedAppleState = await redirectState("/auth/oauth/apple");
    const failedApple = await request("/auth/oauth/apple/callback", {
      method: "POST",
      body: JSON.stringify({
        code: "fixture-failing-apple-code",
        state: failedAppleState,
      }),
    });
    assert.equal(failedApple.response.status, 502);
    assert.equal(failedApple.body.success, false);
    assert.doesNotMatch(
      JSON.stringify(failedApple.body),
      /fixture-failing-apple-code|access-token|refresh-token/i,
    );
  },
);

