import { Router, IRouter } from "express";
import {
  registerController,
  loginController,
  logoutController,
  logoutAllController,
  refreshController,
  getMeController,
  listSessionsController,
  revokeSessionController,
  setup2FAController,
  verify2FAController,
  disable2FAController,
  verifyEmailController,
  resendVerificationController,
  requestPasswordResetController,
  resetPasswordController,
  changePasswordController,
  requestPhoneVerificationController,
  verifyPhoneController,
  oauthGoogleRedirectController,
  oauthGoogleCallbackController,
  oauthAppleRedirectController,
  oauthAppleCallbackController,
} from "../controllers/auth.controller";
import { authenticate } from "../../middleware/authenticate";

const router: IRouter = Router();

// ── Public ────────────────────────────────────────────────────────────────────
router.post("/auth/register", registerController);
router.post("/auth/login", loginController);
router.post("/auth/refresh", refreshController);
router.post("/auth/verify-email", verifyEmailController);
router.post("/auth/resend-verification", resendVerificationController);
router.post("/auth/password/forgot", requestPasswordResetController);
router.post("/auth/password/reset", resetPasswordController);

// ── Authenticated ─────────────────────────────────────────────────────────────
router.post("/auth/logout", authenticate, logoutController);
router.post("/auth/logout-all", authenticate, logoutAllController);
router.get("/auth/me", authenticate, getMeController);

// ── Sessions ──────────────────────────────────────────────────────────────────
router.get("/auth/sessions", authenticate, listSessionsController);
router.delete(
  "/auth/sessions/:sessionId",
  authenticate,
  revokeSessionController,
);

// ── 2FA ───────────────────────────────────────────────────────────────────────
router.post("/auth/2fa/setup", authenticate, setup2FAController);
router.post("/auth/2fa/verify", authenticate, verify2FAController);
router.post("/auth/2fa/disable", authenticate, disable2FAController);
router.post("/auth/password/change", authenticate, changePasswordController);
router.post(
  "/auth/verify-phone/request",
  authenticate,
  requestPhoneVerificationController,
);
router.post("/auth/verify-phone", authenticate, verifyPhoneController);

// ── OAuth ─────────────────────────────────────────────────────────────────────
router.get("/auth/oauth/google", oauthGoogleRedirectController);
router.get("/auth/oauth/google/callback", oauthGoogleCallbackController);
router.get("/auth/oauth/apple", oauthAppleRedirectController);
router.post("/auth/oauth/apple/callback", oauthAppleCallbackController);

export default router;

