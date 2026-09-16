import { Request, Response } from "express";
import {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  logoutAllDevices,
  getActiveSessions,
  changePassword,
  resetPasswordWithToken,
} from "../../login/auth.service";
import { setup2FA, verify2FA, disable2FA } from "../../mfa/twofa.service";
import {
  assertSessionOwned,
  revokeSession,
} from "../../sessions/session.service";
import { db, usersTable } from "../../repositories/database";
import { eq } from "drizzle-orm";
import { config } from "../../app/config";
import {
  createEmailVerificationChallenge,
  verifyEmail,
  requestPhoneVerification,
  verifyPhone,
} from "../../verification/verification.service";
import { requestPasswordReset } from "../../recovery/password-recovery.service";
import { serviceErrorDetails } from "../../errors/service-error";
import {
  RegisterBody,
  LoginBody,
  LogoutBody,
  RefreshTokenBody,
  Verify2faBody,
  Disable2faBody,
  VerifyEmailBody,
  ResendVerificationBody,
  RequestPhoneVerificationBody,
  VerifyPhoneBody,
  RequestPasswordResetBody,
  ResetPasswordBody,
  ChangePasswordBody,
} from "../../validation";
import { parseRegistrationInput } from "../../registration/registration";
import {
  consumeOAuthState,
  createOAuthState,
  exchangeAuthorizationCode,
  getOAuthRedirectUri,
  loginWithOAuth,
} from "../../oauth/oauth.service";
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

function userToProfile(user: {
  id: string;
  email: string;
  role: string;
  createdAt: Date;
  emailVerifiedAt: Date | null;
  phone: string | null;
  phoneVerifiedAt: Date | null;
  professionalDetails: {
    displayName: string;
    businessName: string;
    phone: string;
    serviceCategory: string;
  } | null;
  twoFactorEnabled: boolean;
}) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt.toISOString(),
    emailVerifiedAt: user.emailVerifiedAt?.toISOString() ?? null,
    phone: user.phone,
    phoneVerifiedAt: user.phoneVerifiedAt?.toISOString() ?? null,
    twoFactorEnabled: user.twoFactorEnabled,
    professionalDetails: user.professionalDetails,
  };
}

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

function deviceInfo(req: Request) {
  return {
    userAgent: req.get("user-agent") ?? null,
    ipAddress: req.ip ?? null,
  };
}

function requestValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function authResponse(result: Awaited<ReturnType<typeof loginUser>>) {
  return {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    expiresIn: config.jwtAccessExpiresInSeconds,
    user: userToProfile(result.user),
  };
}

// ── Auth controllers ──────────────────────────────────────────────────────────

export async function registerController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = parseRegistrationInput(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  const { password, role, professionalDetails } = parsed.data;
  const email = parsed.data.email.trim().toLowerCase();
  try {
    const result = await registerUser(
      email,
      password,
      role ?? undefined,
      professionalDetails ?? null,
      deviceInfo(req),
    );
    res.status(201).json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      expiresIn: config.jwtAccessExpiresInSeconds,
      user: userToProfile(result.user),
    });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function loginController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = LoginBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  const { password, totpCode } = parsed.data;
  const email = parsed.data.email.trim().toLowerCase();
  try {
    const result = await loginUser(
      email,
      password,
      totpCode ?? null,
      deviceInfo(req),
    );
    res.json(authResponse(result));
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function logoutController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = LogoutBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    await logoutUser(parsed.data.refreshToken, req.user?.sub);
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function logoutAllController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  try {
    const count = await logoutAllDevices(req.user.sub);
    res.json({ message: `Logged out from ${count} device(s)`, count });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function refreshController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = RefreshTokenBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    const result = await refreshAccessToken(parsed.data.refreshToken);
    res.json({ ...result, expiresIn: config.jwtAccessExpiresInSeconds });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function getMeController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, req.user.sub))
    .limit(1);
  if (!user) {
    res.status(404).json(errBody("User not found"));
    return;
  }
  res.json(userToProfile(user));
}

export async function verifyEmailController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = VerifyEmailBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    await verifyEmail(parsed.data.token);
    res.json({ message: "Email verified successfully" });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function resendVerificationController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = ResendVerificationBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  const email = parsed.data.email.trim().toLowerCase();
  const [user] = await db
    .select({
      id: usersTable.id,
      email: usersTable.email,
      emailVerifiedAt: usersTable.emailVerifiedAt,
    })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);
  if (user && !user.emailVerifiedAt) {
    try {
      await createEmailVerificationChallenge(
        user.id,
        user.email,
        deviceInfo(req),
      );
    } catch (err) {
      req.log.error({ err }, "Failed to create email verification challenge");
    }
  }
  res.json({
    message:
      "If the account exists and needs verification, a new message will be sent",
  });
}

export async function requestPasswordResetController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = RequestPasswordResetBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    await requestPasswordReset(
      parsed.data.email.trim().toLowerCase(),
      deviceInfo(req),
    );
  } catch (err) {
    req.log.error({ err }, "Failed to create password reset challenge");
  }
  res.json({
    message: "If the account exists, password reset instructions will be sent",
  });
}

export async function resetPasswordController(
  req: Request,
  res: Response,
): Promise<void> {
  const parsed = ResetPasswordBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    await resetPasswordWithToken(parsed.data.token, parsed.data.password);
    res.json({ message: "Password reset successfully" });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function changePasswordController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  const parsed = ChangePasswordBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    await changePassword(
      req.user.sub,
      parsed.data.currentPassword,
      parsed.data.newPassword,
    );
    res.json({
      message: "Password changed successfully; all sessions were revoked",
    });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function requestPhoneVerificationController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  const parsed = RequestPhoneVerificationBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    await requestPhoneVerification(
      req.user.sub,
      parsed.data.phone,
      deviceInfo(req),
    );
    res.json({ message: "If supported, a verification code will be sent" });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function verifyPhoneController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  const parsed = VerifyPhoneBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    await verifyPhone(req.user.sub, parsed.data.code);
    res.json({ message: "Phone verified successfully" });
  } catch (err) {
    handleServiceError(err, res);
  }
}

// ── Session controllers ───────────────────────────────────────────────────────

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function listSessionsController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  try {
    const sessions = await getActiveSessions(req.user.sub);
    res.json({
      sessions: sessions.map((s) => ({
        id: s.id,
        createdAt: s.createdAt.toISOString(),
        lastActiveAt: s.lastActiveAt.toISOString(),
        userAgent: s.userAgent ?? null,
        ipAddress: s.ipAddress ?? null,
        isCurrent: s.id === req.user!.sessionId,
      })),
    });
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function revokeSessionController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  const rawId = req.params.sessionId;
  const sessionId = typeof rawId === "string" ? rawId : null;
  if (!sessionId || !UUID_RE.test(sessionId)) {
    res.status(400).json(errBody("Invalid session ID"));
    return;
  }
  try {
    await assertSessionOwned(req.user.sub, sessionId);
    await revokeSession(req.user.sub, sessionId);
    res.json({ message: "Session revoked successfully" });
  } catch (err) {
    handleServiceError(err, res);
  }
}

// ── 2FA controllers ───────────────────────────────────────────────────────────

export async function setup2FAController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  try {
    const result = await setup2FA(req.user.sub, req.user.email);
    res.json(result);
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function verify2FAController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  const parsed = Verify2faBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    const result = await verify2FA(req.user.sub, parsed.data.totpCode);
    res.json(result);
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function disable2FAController(
  req: Request,
  res: Response,
): Promise<void> {
  if (!req.user) {
    res.status(401).json(errBody("Unauthorized"));
    return;
  }
  const parsed = Disable2faBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json(formatZodError(parsed.error));
    return;
  }
  try {
    const result = await disable2FA(req.user.sub, parsed.data.totpCode);
    res.json(result);
  } catch (err) {
    handleServiceError(err, res);
  }
}

// ── OAuth controllers ─────────────────────────────────────────────────────────

export async function oauthGoogleRedirectController(
  _req: Request,
  res: Response,
): Promise<void> {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId)
      throw Object.assign(new Error("Google OAuth is not configured."), {
        status: 503,
      });
    const redirectUri = getOAuthRedirectUri("google");
    const state = await createOAuthState("google");
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid email profile",
      state,
      access_type: "offline",
      prompt: "select_account",
    }).toString();
    res.redirect(url.toString());
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function oauthGoogleCallbackController(
  req: Request,
  res: Response,
): Promise<void> {
  const state = requestValue(req.query.state);
  try {
    await consumeOAuthState(state, "google");
    const providerError = requestValue(req.query.error);
    if (providerError) {
      res.status(400).json(errBody("Google sign-in was cancelled."));
      return;
    }
    const code = requestValue(req.query.code);
    const identity = await exchangeAuthorizationCode("google", code ?? "");
    const result = await loginWithOAuth(identity, deviceInfo(req));
    res.json(authResponse(result));
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function oauthAppleRedirectController(
  _req: Request,
  res: Response,
): Promise<void> {
  try {
    const clientId = process.env.APPLE_CLIENT_ID;
    if (!clientId)
      throw Object.assign(new Error("Apple OAuth is not configured."), {
        status: 503,
      });
    const redirectUri = getOAuthRedirectUri("apple");
    const state = await createOAuthState("apple");
    const url = new URL("https://appleid.apple.com/auth/authorize");
    url.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "name email",
      response_mode: "form_post",
      state,
    }).toString();
    res.redirect(url.toString());
  } catch (err) {
    handleServiceError(err, res);
  }
}

export async function oauthAppleCallbackController(
  req: Request,
  res: Response,
): Promise<void> {
  const body = req.body as Record<string, unknown>;
  const state = requestValue(body?.state);
  try {
    await consumeOAuthState(state, "apple");
    const providerError = requestValue(body?.error);
    if (providerError) {
      res.status(400).json(errBody("Apple sign-in was cancelled."));
      return;
    }
    const code = requestValue(body?.code);
    const identity = await exchangeAuthorizationCode("apple", code ?? "");
    const result = await loginWithOAuth(identity, deviceInfo(req));
    res.json(authResponse(result));
  } catch (err) {
    handleServiceError(err, res);
  }
}

