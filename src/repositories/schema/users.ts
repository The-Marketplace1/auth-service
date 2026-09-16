import {
  pgTable,
  text,
  uuid,
  timestamp,
  boolean,
  pgEnum,
  jsonb,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const userRoleEnum = pgEnum("user_role", [
  "customer",
  "professional",
  "admin",
]);

export type ProfessionalDetails = {
  displayName: string;
  businessName: string;
  phone: string;
  serviceCategory: string;
};

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  role: userRoleEnum("role").notNull().default("customer"),
  professionalDetails: jsonb(
    "professional_details",
  ).$type<ProfessionalDetails | null>(),
  emailVerifiedAt: timestamp("email_verified_at", { withTimezone: true }),
  phone: text("phone"),
  phoneVerifiedAt: timestamp("phone_verified_at", { withTimezone: true }),
  twoFactorSecret: text("two_factor_secret"),
  twoFactorEnabled: boolean("two_factor_enabled").notNull().default(false),
  oauthProvider: text("oauth_provider"),
  oauthProviderId: text("oauth_provider_id"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
});

export const insertUserSchema = createInsertSchema(usersTable).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof usersTable.$inferSelect;

