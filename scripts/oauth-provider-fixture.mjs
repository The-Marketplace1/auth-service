import http from "node:http";
import { createSign, generateKeyPairSync } from "node:crypto";

const port = Number(process.env.OAUTH_PROVIDER_PORT ?? 8100);
const { privateKey, publicKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});
const publicJwk = publicKey.export({ format: "jwk" });
const key = {
  ...publicJwk,
  kid: "oauth-fixture-key",
  alg: "ES256",
  use: "sig",
};

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

async function formBody(req) {
  let body = "";
  for await (const chunk of req) body += chunk;
  return new URLSearchParams(body);
}

function signedAppleIdentityToken() {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({
    alg: "ES256",
    kid: key.kid,
    typ: "JWT",
  });
  const payload = encode({
    iss: "https://appleid.apple.com",
    aud: process.env.APPLE_CLIENT_ID ?? "com.marketplace.e2e",
    sub: "apple-e2e-user",
    email: "apple.e2e@example.com",
    email_verified: true,
    exp: Math.floor(Date.now() / 1000) + 300,
  });
  const signer = createSign("SHA256");
  signer.update(`${header}.${payload}`);
  signer.end();
  const signature = signer.sign({
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);

  if (req.method === "POST" && url.pathname === "/google/token") {
    const body = await formBody(req);
    const code = body.get("code");
    if (code === "fixture-google-code") {
      json(res, 200, { access_token: "fixture-google-access-token" });
      return;
    }
    json(res, 400, { error: "invalid_grant" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/google/userinfo") {
    if (req.headers.authorization === "Bearer fixture-google-access-token") {
      json(res, 200, {
        sub: "google-e2e-user",
        email: "google.e2e@example.com",
        email_verified: true,
      });
      return;
    }
    json(res, 401, { error: "invalid_token" });
    return;
  }

  if (req.method === "POST" && url.pathname === "/apple/token") {
    const body = await formBody(req);
    const code = body.get("code");
    if (code === "fixture-apple-code") {
      json(res, 200, { id_token: signedAppleIdentityToken() });
      return;
    }
    json(res, 400, { error: "invalid_grant" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/apple/keys") {
    json(res, 200, { keys: [key] });
    return;
  }

  json(res, 404, { error: "not_found" });
});

server.listen(port, "127.0.0.1", () => {
  console.log(`OAuth provider fixture listening on ${port}`);
});

