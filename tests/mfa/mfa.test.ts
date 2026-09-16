import assert from "node:assert/strict";
import test from "node:test";
import speakeasy from "speakeasy";

test("TOTP codes verify for the generated secret and reject a wrong code", () => {
  const secret = speakeasy.generateSecret({ length: 20 });
  const token = speakeasy.totp({
    secret: secret.base32,
    encoding: "base32",
  });

  assert.equal(
    speakeasy.totp.verify({
      secret: secret.base32,
      encoding: "base32",
      token,
      window: 1,
    }),
    true,
  );
  assert.equal(
    speakeasy.totp.verify({
      secret: secret.base32,
      encoding: "base32",
      token: "000000",
      window: 0,
    }),
    false,
  );
});

