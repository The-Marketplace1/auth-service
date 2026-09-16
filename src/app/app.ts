import express, {
  type Express,
  Request,
  Response,
  NextFunction,
} from "express";
import cors from "cors";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import pinoHttp from "pino-http";
import router from "../api/routes";
import { logger } from "../utils/logger";
import { config } from "./config";
import { observeRequest } from "../security/metrics";

const app: Express = express();
app.set("trust proxy", 1);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);

// ── Request logging ───────────────────────────────────────────────────────────
app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return { id: req.id, method: req.method, url: req.url?.split("?")[0] };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  }),
);

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(
  cors({
    origin: (origin, callback) => {
      if (
        !origin ||
        (config.corsOrigins.length === 0 && config.nodeEnv !== "production")
      ) {
        callback(null, true);
        return;
      }
      callback(null, config.corsOrigins.includes(origin));
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  }),
);

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: true, limit: "64kb" }));

// ── Global rate limit: 200 req / 15 min per IP ────────────────────────────────
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({
        success: false,
        error: { message: "Too many requests, please try again later." },
      });
    },
  }),
);

// ── Strict rate limit for auth mutations: 20 req / 15 min per IP ─────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({
      success: false,
      error: { message: "Too many auth attempts, please try again later." },
    });
  },
});
app.use("/api/auth/register", authLimiter);
app.use("/api/auth/login", authLimiter);

app.use((_req, res, next) => {
  res.on("finish", () => observeRequest(res.statusCode));
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use("/api", router);

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((_req: Request, res: Response) => {
  res.status(404).json({ success: false, error: { message: "Not found" } });
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  const e = err as { status?: number; statusCode?: number; message?: string };
  const status = e.status ?? e.statusCode ?? 500;
  const message =
    status < 500 ? (e.message ?? "Bad request") : "Internal server error";
  req.log.error({ err }, "Unhandled error");
  res.status(status).json({ success: false, error: { message } });
});

export default app;

