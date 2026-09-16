import { db, authAuditEventsTable } from "../repositories/database";
import { logger } from "../utils/logger";
import { config } from "../app/config";
import {
  publishAuthEvent,
  type AuthEventSinkPayload,
} from "../integrations/event-sink";

export type AuthEventType =
  | "user.created"
  | "user.verified"
  | "user.login"
  | "user.logout"
  | "user.password_changed"
  | "user.password_reset"
  | "user.mfa_enabled"
  | "user.mfa_disabled"
  | "session.created"
  | "session.revoked"
  | "account.locked"
  | "account.unlocked"
  | "verification.requested"
  | "password_reset.requested"
  | "phone_verification.requested";

export interface AuthEventContext {
  userId?: string | null;
  sessionId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
  delivery?: Record<string, unknown>;
}

async function publishToSink(
  eventType: AuthEventType,
  context: AuthEventContext,
): Promise<void> {
  if (!config.eventSinkUrl) return;

  try {
    const payload: AuthEventSinkPayload = {
      type: eventType,
      occurredAt: new Date().toISOString(),
      data: {
        userId: context.userId ?? null,
        sessionId: context.sessionId ?? null,
        metadata: context.metadata ?? {},
        delivery: context.delivery ?? null,
      },
    };
    await publishAuthEvent(config.eventSinkUrl, payload);
  } catch (err) {
    logger.error({ err, eventType }, "Auth event sink publish failed");
  }
}

/**
 * Persist an auditable event and optionally publish a delivery request.
 * Sensitive delivery values are sent only to the configured internal sink and
 * are deliberately excluded from the audit record and service logs.
 */
export async function emitAuthEvent(
  eventType: AuthEventType,
  context: AuthEventContext = {},
): Promise<void> {
  await db.insert(authAuditEventsTable).values({
    eventType,
    userId: context.userId ?? null,
    sessionId: context.sessionId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    metadata: context.metadata ?? null,
  });

  void publishToSink(eventType, context);
  logger.info(
    {
      eventType,
      userId: context.userId ?? undefined,
      sessionId: context.sessionId ?? undefined,
    },
    "Auth event emitted",
  );
}

