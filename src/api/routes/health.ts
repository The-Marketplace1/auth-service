import { Router, type IRouter } from "express";
import { HealthCheckResponse } from "../../validation";
import { pool } from "../../repositories/database";
import { getRedis } from "../../utils/redis";
import { config } from "../../app/config";
import { renderPrometheusMetrics } from "../../security/metrics";

const router: IRouter = Router();

router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json(data);
});

router.get("/readyz", async (_req, res): Promise<void> => {
  let database = "ok";
  let redis = config.redisUrl ? "ok" : "degraded";
  try {
    await pool.query("select 1");
  } catch {
    database = "unavailable";
  }
  try {
    await getRedis();
  } catch {
    redis = "unavailable";
  }

  const ready =
    database === "ok" && (redis === "ok" || config.nodeEnv !== "production");
  res.status(ready ? 200 : 503).json({
    status: ready ? "ready" : "not_ready",
    dependencies: { database, redis },
  });
});

router.get("/metrics", (_req, res) => {
  res.type("text/plain").send(renderPrometheusMetrics());
});

export default router;

