import { Router, IRouter } from "express";
import {
  listUsersController,
  getUserController,
  updateUserController,
  deleteUserController,
  getUserStatsController,
} from "../controllers/user.controller";
import { authenticate } from "../../middleware/authenticate";
import { requireRole } from "../../middleware/rbac";

const router: IRouter = Router();

router.get(
  "/users/stats",
  authenticate,
  requireRole("admin"),
  getUserStatsController,
);
router.get("/users", authenticate, requireRole("admin"), listUsersController);
router.get("/users/:id", authenticate, requireRole("admin"), getUserController);
router.patch(
  "/users/:id",
  authenticate,
  requireRole("admin"),
  updateUserController,
);
router.delete(
  "/users/:id",
  authenticate,
  requireRole("admin"),
  deleteUserController,
);

export default router;

