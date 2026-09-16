import { createServer } from "node:http";

const port = Number(process.env.TEST_EVENT_SINK_PORT ?? 8099);
const events = [];

const server = createServer(async (req, res) => {
  res.setHeader("content-type", "application/json");
  res.setHeader("cache-control", "no-store");

  if (req.method === "GET" && req.url?.startsWith("/events")) {
    res.statusCode = 200;
    res.end(JSON.stringify({ events }));
    return;
  }

  if (req.method === "DELETE" && req.url === "/events") {
    events.length = 0;
    res.statusCode = 204;
    res.end();
    return;
  }

  if (req.method === "POST" && req.url === "/events") {
    let body = "";
    for await (const chunk of req) body += chunk;
    try {
      events.push(JSON.parse(body));
      res.statusCode = 202;
      res.end(JSON.stringify({ accepted: true }));
    } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ accepted: false }));
    }
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(port, "127.0.0.1", () => {
  console.log(`test event sink listening on 127.0.0.1:${port}`);
});

