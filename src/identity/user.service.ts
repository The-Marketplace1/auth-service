import { db, usersTable } from "../repositories/database";
import { eq, ilike, or, sql, count, desc } from "drizzle-orm";
import { logger } from "../utils/logger";
import type { UserRole } from "../types/auth";

export type { UserRole } from "../types/auth";

interface ListUsersOptions {
  page?: number;
  limit?: number;
  role?: UserRole;
  search?: string;
}

export async function listUsers(opts: ListUsersOptions = {}) {
  const { page = 1, limit = 20, role, search } = opts;
  const offset = (page - 1) * limit;

  let query = db.select().from(usersTable).$dynamic();
  let countQuery = db.select({ total: count() }).from(usersTable).$dynamic();

  const filters = [];
  if (role) filters.push(eq(usersTable.role, role));
  if (search) {
    filters.push(ilike(usersTable.email, `%${search}%`));
  }

  if (filters.length > 0) {
    const combined = filters.length === 1 ? filters[0] : or(...filters);
    if (combined) {
      query = query.where(combined);
      countQuery = countQuery.where(combined);
    }
  }

  const [users, countResult] = await Promise.all([
    query.orderBy(desc(usersTable.createdAt)).limit(limit).offset(offset),
    countQuery,
  ]);

  const total = countResult[0]?.total ?? 0;

  return {
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      role: u.role,
      createdAt: u.createdAt.toISOString(),
      twoFactorEnabled: u.twoFactorEnabled,
      professionalDetails: u.professionalDetails,
    })),
    total,
    page,
    limit,
  };
}

export async function getUserById(id: string) {
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, id))
    .limit(1);
  if (!user) {
    throw Object.assign(new Error("User not found"), { status: 404 });
  }
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt.toISOString(),
    twoFactorEnabled: user.twoFactorEnabled,
    professionalDetails: user.professionalDetails,
  };
}

export async function updateUserRole(id: string, role: UserRole) {
  const [user] = await db
    .update(usersTable)
    .set({ role })
    .where(eq(usersTable.id, id))
    .returning();

  if (!user) {
    throw Object.assign(new Error("User not found"), { status: 404 });
  }

  logger.info({ userId: id, newRole: role }, "User role updated");

  return {
    id: user.id,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt.toISOString(),
    twoFactorEnabled: user.twoFactorEnabled,
    professionalDetails: user.professionalDetails,
  };
}

export async function deleteUser(id: string) {
  const [user] = await db
    .delete(usersTable)
    .where(eq(usersTable.id, id))
    .returning();
  if (!user) {
    throw Object.assign(new Error("User not found"), { status: 404 });
  }
  logger.info({ userId: id }, "User deleted");
}

export async function getUserStats() {
  const [allUsers, byRoleResult] = await Promise.all([
    db.select({ total: count() }).from(usersTable),
    db
      .select({ role: usersTable.role, cnt: count() })
      .from(usersTable)
      .groupBy(usersTable.role),
  ]);

  const roleCounts: Record<string, number> = {
    customer: 0,
    professional: 0,
    admin: 0,
  };
  for (const r of byRoleResult) {
    roleCounts[r.role] = r.cnt;
  }

  const last7Days = await db
    .select({
      date: sql<string>`date_trunc('day', ${usersTable.createdAt})::date::text`,
      count: count(),
    })
    .from(usersTable)
    .where(sql`${usersTable.createdAt} >= now() - interval '7 days'`)
    .groupBy(sql`date_trunc('day', ${usersTable.createdAt})`)
    .orderBy(sql`date_trunc('day', ${usersTable.createdAt})`);

  return {
    total: allUsers[0]?.total ?? 0,
    byRole: roleCounts,
    recentRegistrations: last7Days.map((d) => ({
      date: d.date,
      count: d.count,
    })),
  };
}

