export type UserRole = "customer" | "professional" | "admin";

export interface DeviceInfo {
  userAgent?: string | null;
  ipAddress?: string | null;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

