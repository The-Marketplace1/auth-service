import bcrypt from "bcryptjs";
import pg from "pg";

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const password = process.env.SEED_PASSWORD;
if (!password) {
  throw new Error("SEED_PASSWORD must be set when running the seed script");
}
const SALT_ROUNDS = 12;

const USERS = [
  { email: "admin@marketplace.dev", role: "admin" },
  { email: "pro@marketplace.dev", role: "professional" },
  { email: "customer@marketplace.dev", role: "customer" },
  { email: "dev@marketplace.dev", role: "professional" },
];

async function main() {
  console.log("Hashing password (12 rounds)...");
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  console.log("Hash:", hash.slice(0, 30) + "...");

  for (const u of USERS) {
    await pool.query(
      `INSERT INTO users (email, password, role)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE SET password = $2, role = $3`,
      [u.email, hash, u.role],
    );
    console.log("✓ Seeded:", u.email, "→", u.role);
  }

  const { rows } = await pool.query(
    "SELECT email, role, created_at FROM users ORDER BY created_at",
  );
  console.log("\nAll users in DB:");
  rows.forEach((r) => console.log(" -", r.email, "|", r.role));
  await pool.end();
}

main().catch((e) => {
  console.error("Seed error:", e.message);
  process.exit(1);
});

