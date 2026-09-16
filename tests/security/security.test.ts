import assert from "node:assert/strict";
import test from "node:test";
import { assertStrongPassword } from "../../src/credentials/password-policy";

test("security password policy rejects short and predictable passwords", () => {
  for (const password of ["short", "password", "Password1"]) {
    assert.throws(() => assertStrongPassword(password));
  }
});

test("security password policy accepts a high-entropy password", () => {
  assert.doesNotThrow(() => assertStrongPassword("Correct-Horse-Battery-77!"));
});

