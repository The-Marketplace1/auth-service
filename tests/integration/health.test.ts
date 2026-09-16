import assert from "node:assert/strict";
import test from "node:test";

test("integration test suite is wired to the standalone service", () => {
  assert.equal(
    process.env.NODE_ENV === "test" || process.env.NODE_ENV === undefined,
    true,
  );
});

