#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
pnpm install --frozen-lockfile
pnpm run codegen
pnpm run typecheck

if [[ -n "${DATABASE_URL:-}" ]]; then
  pnpm run db:push
fi

