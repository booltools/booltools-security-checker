#!/bin/sh
set -e

echo "Starting Booltools Security Checker..."

if [ ! -f "/app/data/security_rules.db" ] && [ -f "/app/security_rules.db" ]; then
  cp /app/security_rules.db /app/data/security_rules.db
fi

export DB_PATH="${DB_PATH:-/app/data/security_rules.db}"
export PORT="${PORT:-8787}"

echo "Backend starting on port $PORT"
exec ./server
