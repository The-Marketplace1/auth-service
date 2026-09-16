import { pgTable, uuid, text, timestamp, boolean } from "drizzle-orm/pg-core";
import { usersTable } from "./users";

export const sessionsTable = pgTable("sessions", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id")
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  lastActiveAt: timestamp("last_active_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  isRevoked: boolean("is_revoked").notNull().default(false),
  userAgent: text("user_agent"),
  ipAddress: text("ip_address"),
});

export type Session = typeof sessionsTable.$inferSelect;

