import { Request, Response } from "express";
import {
  listUsers,
  getUserById,
  updateUserRole,
  deleteUser,
  getUserStats,
  UserRole,
} from "../../identity/user.service";
import {
  ListUsersQueryParams,
  GetUserParams,
  UpdateUserParams,
  UpdateUserBody,
  DeleteUserParams,
} from "../../validation";
import { serviceErrorDetails } from "../../errors/service-error";

// ── Shared response shapes ────────────────────────────────────────────────────

type ErrorEnvelope = {
  success: false;
  error: { message: string; fields?: Record<string, string> };
};

function errBody(
  message: string,
  fields?: Record<string, string>,
): ErrorEnvelope {
  return { success: false, error: fields ? { message, fields } : { message } };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

interface ZodLike {
  issues: Array<{ path: (string | number)[]; message: string }>;
}

function formatZodError(err: ZodLike): ErrorEnvelope {
  const fields: Record<string, string> = {};
  for (const issue of err.issues) {
    const path = issue.path.join(".") || "body";
    if (!fields[path]) fields[path] = issue.message;
  }
  return errBody("Validation failed", fields);
}

function handleServiceError(err: unknown, res: Response): void {
  const details = serviceErrorDetails(err);
  res.status(details.status).json(errBody(details.message, details.fields));
}

// ── Controllers ───────────────────────────────────────────────────────────────

export async function listUsersController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = ListUsersQueryParams.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  const { page, limit, role, search } = parsed.data;
  try {
    const result = await listUsers({
      page: page ?? 1,
      limit: limit ?? 20,
      role: role as UserRole | undefined,
      search: search ?? undefined,
    });
    res.json(result);
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function getUserController(
  req: Request,
  res: Response,
): Promise<void> {
  const params = GetUserParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json(formatZodError(params.error));
    return;
  }
  try {
    const user = await getUserById(params.data.id);
    res.json(user);
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function updateUserController(
  req: Request,
  res: Response,
): Promise<void> {
  const params = UpdateUserParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json(formatZodError(params.error));
    return;
  }
  const body = UpdateUserBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json(formatZodError(body.error));
    return;
  }
  try {
    const user = await updateUserRole(
      params.data.id,
      body.data.role as UserRole,
    );
    res.json(user);
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function deleteUserController(
  req: Request,
  res: Response,
): Promise<void> {
  const params = DeleteUserParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json(formatZodError(params.error));
    return;
  }
  try {
    await deleteUser(params.data.id);
    res.sendStatus(204);
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function getUserStatsController(
  _req: Request,
  res: Response,
): Promise<void> {
  try {
    const stats = await getUserStats();
    res.json(stats);
  } catch (err) {
    handleServiceError(err, res);
  }
}

