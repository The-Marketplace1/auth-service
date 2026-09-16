import { pgTable, uuid, text, timestamp, jsonb } from "drizzle-orm/pg-core";
import { usersTable } from "./users";

export const authAuditEventsTable = pgTable("auth_audit_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  eventType: text("event_type").notNull(),
  userId: uuid("user_id").references(() => usersTable.id, {
    onDelete: "set null",
  }),
  sessionId: uuid("session_id"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  metadata: jsonb("metadata").$type<Record<string, unknown> | null>(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export type AuthAuditEvent = typeof authAuditEventsTable.$inferSelect;

