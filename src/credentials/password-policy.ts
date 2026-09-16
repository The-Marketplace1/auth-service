export function assertStrongPassword(password: string): void {
  if (
    password.length < 12 ||
    !/[A-Z]/.test(password) ||
    !/[a-z]/.test(password) ||
    !/[0-9]/.test(password)
  ) {
    throw Object.assign(
      new Error(
        "Password must be at least 12 characters and include upper, lower, and numeric characters",
      ),
      { status: 400 },
    );
  }
}

