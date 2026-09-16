import { Request, Response, NextFunction } from "express";
import { verifyAccessToken, JwtPayload } from "../tokens/jwt";
import { getRedis } from "../utils/redis";
import { sessionRefreshKey } from "../sessions/session.service";

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

function errBody(message: string) {
  return { success: false, error: { message } };
}

export async function authenticate(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json(errBody("Missing or invalid Authorization header"));
    return;
  }

  const token = authHeader.slice(7);
  try {
    const payload = verifyAccessToken(token);
    if (!payload.sub || !payload.sessionId) {
      res.status(401).json(errBody("Invalid access token claims"));
      return;
    }
    const redis = await getRedis();
    const sessionToken = await redis.get(
      sessionRefreshKey(payload.sub, payload.sessionId),
    );
    if (!sessionToken) {
      res.status(401).json(errBody("Session revoked or expired"));
      return;
    }
    req.user = payload;
    next();
  } catch {
    res.status(401).json(errBody("Invalid or expired access token"));
  }
}

