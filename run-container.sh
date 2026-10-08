#!/usr/bin/env bash
set -euo pipefail

docker run --rm -p 8080:8080 \
  -e DB_HOST=localhost \
  -e DB_PORT=5432 \
  -e DB_NAME=userdb \
  -e DB_USER=postgres \
  -e DB_PASSWORD=postgres \
  -e JWT_SECRET=test-secret-key-that-is-at-least-32-bytes-long \
  user-service:test