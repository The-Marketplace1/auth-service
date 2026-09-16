import type { UserRole } from "../types/auth";

const roleHierarchy: Record<UserRole, number> = {
  customer: 1,
  professional: 2,
  admin: 3,
};

export function isUserRole(value: unknown): value is UserRole {
  return value === "customer" || value === "professional" || value === "admin";
}

export function hasMinimumRole(actual: UserRole, required: UserRole): boolean {
  return roleHierarchy[actual] >= roleHierarchy[required];
}

