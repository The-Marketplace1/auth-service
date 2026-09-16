import assert from "node:assert/strict";
import test from "node:test";
import { RegisterBody } from "../../src/validation";
import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  type JwtPayload,
} from "../../src/tokens/jwt";
import { assertStrongPassword } from "../../src/credentials/password-policy";
import { parseRegistrationInput } from "../../src/registration/registration";
import type { UserRole } from "../../src/types/auth";

const strongPassword = "StrongPassword123";
const professionalDetails = {
  displayName: "Amina Bello",
  businessName: "Amina Home Services",
  phone: "+2348012345678",
  serviceCategory: "Home maintenance",
};

test("customer registration stays minimal", () => {
  const result = parseRegistrationInput({
    email: "customer@example.com",
    password: strongPassword,
  });

  assert.equal(result.success, true);
  if (result.success) {
    assert.equal(result.data.role, undefined);
    assert.equal(result.data.professionalDetails, undefined);
  }
});

test("professional registration requires identity onboarding details", () => {
  const missingDetails = parseRegistrationInput({
    email: "professional@example.com",
    password: strongPassword,
    role: "professional",
  });
  assert.equal(missingDetails.success, false);

  const complete = parseRegistrationInput({
    email: "professional@example.com",
    password: strongPassword,
    role: "professional",
    professionalDetails,
  });
  assert.equal(complete.success, true);
});

test("admin cannot self-register and professional details cannot be attached to customers", () => {
  const adminRegistration = RegisterBody.safeParse({
    email: "admin@example.com",
    password: strongPassword,
    role: "admin",
  });
  assert.equal(adminRegistration.success, false);

  const customerWithProfessionalDetails = parseRegistrationInput({
    email: "customer@example.com",
    password: strongPassword,
    professionalDetails,
  });
  assert.equal(customerWithProfessionalDetails.success, false);
});

test("password policy rejects weak passwords and accepts strong passwords", () => {
  assert.throws(
    () => assertStrongPassword("weak"),
    (error: unknown) => {
      return (error as { status?: number }).status === 400;
    },
  );
  assert.doesNotThrow(() => assertStrongPassword(strongPassword));
});

test("refresh tokens carry a unique jti and preserve the session identity", () => {
  const payload: Omit<JwtPayload, "iat" | "exp" | "jti"> = {
    sub: "00000000-0000-0000-0000-000000000001",
    email: "customer@example.com",
    role: "customer",
    sessionId: "00000000-0000-0000-0000-000000000002",
  };

  const first = signRefreshToken(payload);
  const second = signRefreshToken(payload);
  const firstPayload = verifyRefreshToken(first);
  const secondPayload = verifyRefreshToken(second);

  assert.notEqual(first, second);
  assert.notEqual(firstPayload.jti, secondPayload.jti);
  assert.equal(firstPayload.sessionId, payload.sessionId);
  assert.equal(secondPayload.role, payload.role);
});

test("access tokens preserve role claims for gateway authorization", () => {
  const roles: UserRole[] = ["customer", "professional", "admin"];
  for (const role of roles) {
    const token = signAccessToken({
      sub: "00000000-0000-0000-0000-000000000001",
      email: `${role}@example.com`,
      role,
      sessionId: "00000000-0000-0000-0000-000000000002",
    });
    assert.equal(verifyAccessToken(token).role, role);
  }
});

