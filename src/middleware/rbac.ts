import { Request, Response, NextFunction } from "express";
import { hasMinimumRole, isUserRole } from "../authorization/roles";
import type { UserRole } from "../types/auth";

function errBody(message: string) {
  return { success: false, error: { message } };
}

export function requireRole(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json(errBody("Unauthorized"));
      return;
    }

    if (!isUserRole(req.user.role)) {
      res.status(403).json(errBody("Forbidden: invalid role"));
      return;
    }
    const hasRole = roles.some((role) => hasMinimumRole(req.user!.role, role));

    if (!hasRole) {
      res.status(403).json(errBody("Forbidden: insufficient permissions"));
      return;
    }

    next();
  };
}

