#!/usr/bin/env bash
# Security gate for the TaskFlow users service.
#
# Fails (exit 1) if anything that could leak or weaken the RS256 signing key is in the repository:
#   1. a tracked *.pem or .env file
#   2. a real PEM private key (header followed by key material) in any tracked file
#   3. a base64-encoded PEM private key (a JWT_PRIVATE_KEY_BASE64 value) in any tracked file
#   4. a .dockerignore that would let *.pem or .env into the image build context
#   5. a Dockerfile that copies a key in or bakes JWT_PRIVATE_KEY_* into the image
#   6. a default value for jwt.private-key-path, or a leftover HS256 jwt.secret property
#   7. a password, secret or token written into the Spring properties or a compose/stack file,
#      including as a ${VAR:default} fallback
#
# General secrets (API tokens, cloud keys, anything else, across the whole git history) are covered by
# gitleaks in CI. This script covers what gitleaks misses: weak default passwords and key handling.
#
# Run from the project root:  ./scripts/security-check.sh
# Optional: ./scripts/security-check.sh --image-dir <dir>  also scans an exported image filesystem for keys.

set -uo pipefail

IMAGE_DIR=""
if [[ "${1:-}" == "--image-dir" ]]; then
  IMAGE_DIR="${2:?--image-dir needs a directory}"
fi

failures=0
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
pass() { echo "ok    $*"; }

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Run this from inside the users service git repository." >&2
  exit 2
fi

# A PEM private key block with real content: the header, then a line of base64 key material.
# TestJwtKeys builds "-----BEGIN PRIVATE KEY-----\n" + body in code, which has no key material
# after the header, so it does not match.
PEM_KEY_RE='-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----\s*\r?\n[A-Za-z0-9+/=]{40,}'

# base64 of "-----BEGIN PRIVATE KEY-----" and "-----BEGIN RSA PRIVATE KEY-----":
# what a JWT_PRIVATE_KEY_BASE64 value starts with.
# Split in two so this script does not match itself.
B64_PKCS8='LS0tLS1CRUdJTiBQ''UklWQVRFIEtFWS0tLS0t'
B64_PKCS1='LS0tLS1CRUdJTiBS''U0EgUFJJVkFURSBLRVktLS0tLQ'

# True when the file contains a real PEM private key block.
has_pem_key() { PEM_KEY_RE="$PEM_KEY_RE" perl -0777 -ne 'exit($_ =~ $ENV{PEM_KEY_RE} ? 0 : 1)' "$1"; }

# 1. Tracked key and env files
tracked_secrets=$(git ls-files | grep -E '(^|/)[^/]*\.pem$|(^|/)\.env$' || true)
if [[ -n "$tracked_secrets" ]]; then
  fail "key or .env files are tracked by git:"; echo "$tracked_secrets" | sed 's/^/        /'
else
  pass "no *.pem or .env files tracked"
fi

# 2 and 3. Key material inside tracked files (binary files are skipped)
pem_hits=""
b64_hits=""
while IFS= read -r -d '' f; do
  [[ -f "$f" ]] || continue
  grep -Iq . "$f" 2>/dev/null || continue
  if has_pem_key "$f"; then pem_hits+="$f"$'\n'; fi
  if grep -qE "$B64_PKCS8|$B64_PKCS1" "$f"; then b64_hits+="$f"$'\n'; fi
done < <(git ls-files -z)

if [[ -n "$pem_hits" ]]; then
  fail "PEM private key material in tracked files:"; printf '%s' "$pem_hits" | sed 's/^/        /'
else
  pass "no PEM private key material in tracked files"
fi
if [[ -n "$b64_hits" ]]; then
  fail "base64-encoded private key (JWT_PRIVATE_KEY_BASE64 value) in tracked files:"; printf '%s' "$b64_hits" | sed 's/^/        /'
else
  pass "no base64-encoded private key in tracked files"
fi

# 4. .dockerignore must keep keys and .env out of the build context
if [[ -f Dockerfile ]]; then
  if [[ ! -f .dockerignore ]]; then
    fail ".dockerignore is missing, so *.pem and .env would enter the Docker build context"
  else
    grep -qE '^\s*(\*\*/)?\*\.pem\s*$' .dockerignore || fail ".dockerignore does not exclude *.pem"
    grep -qE '^\s*(\*\*/)?\.env\s*$'   .dockerignore || fail ".dockerignore does not exclude .env"
    if grep -qE '^\s*(\*\*/)?\*\.pem\s*$' .dockerignore && grep -qE '^\s*(\*\*/)?\.env\s*$' .dockerignore; then
      pass ".dockerignore excludes *.pem and .env"
    fi
  fi

  # 5. Dockerfile must not copy a key in or bake key settings into the image
  if grep -nEi '^\s*(COPY|ADD)\b.*(\.pem|\.taskflow|keys/)' Dockerfile; then
    fail "Dockerfile copies a key file into the image (lines above)"
  elif grep -nE '^\s*(ENV|ARG)\b.*JWT_PRIVATE_KEY_(BASE64|PATH)' Dockerfile; then
    fail "Dockerfile sets JWT_PRIVATE_KEY_* (lines above); pass it at run time instead"
  else
    pass "Dockerfile copies no keys and sets no JWT_PRIVATE_KEY_*"
  fi
fi

# 6. Spring properties: no default key path, no HS256 secret
props=$(git ls-files 'src/main/resources/application*.properties' 'src/main/resources/application*.yml' 'src/main/resources/application*.yaml')
if [[ -n "$props" ]]; then
  # shellcheck disable=SC2086
  if grep -nE 'private-key-path\s*[=:]\s*\$\{JWT_PRIVATE_KEY_PATH:' $props; then
    fail "jwt.private-key-path has a default value (lines above); a missing key must stop startup"
  else
    pass "jwt.private-key-path has no default"
  fi
  # shellcheck disable=SC2086
  if grep -nE '^\s*jwt\.secret\s*[=:]|^\s*secret\s*:' $props; then
    fail "an HS256 jwt.secret property is still present (lines above); the service signs with RS256 only"
  else
    pass "no HS256 jwt.secret property"
  fi
  # 7a. No password, secret, token or API key written into the properties, not even as a ${VAR:default}.
  # spring.datasource.password=${DB_PASSWORD} is fine; ${DB_PASSWORD:password} or password=secret is not.
  # shellcheck disable=SC2086
  if grep -nEi '^\s*[a-z0-9._-]*(password|secret|token|api-?key)[a-z0-9._-]*\s*[=:]\s*(\$\{[A-Za-z0-9_.]+:[^}]+\}|[^$[:space:]{].*)\s*$' $props; then
    fail "a password, secret or token has a value or default in the Spring properties (lines above); read it from the environment with no default"
  else
    pass "no passwords, secrets or tokens in the Spring properties"
  fi
fi

# 7b. Compose and stack files: no literal passwords, secrets or tokens, and no ${VAR:-default} for them.
# ${DB_PASSWORD_ENV}, ${DB_PASSWORD_ENV:?msg} and *_FILE pointing at /run/secrets are fine.
compose_files=$(git ls-files | grep -E '(^|/)(docker-compose|compose|stack-)[^/]*\.ya?ml$' || true)
if [[ -n "$compose_files" ]]; then
  # shellcheck disable=SC2086
  if grep -nE '^\s*-?\s*[A-Z0-9_]*(PASSWORD|SECRET|TOKEN)[A-Z0-9_]*\s*[:=]\s*("?\$\{[A-Z0-9_]+:?-[^}]+\}"?|[^$[:space:]"].*|"[^$].*)\s*$' $compose_files \
      | grep -vE '_FILE\s*[:=]'; then
    fail "a password, secret or token is written into a compose or stack file (lines above); pass it through .env or a secret"
  else
    pass "no passwords, secrets or tokens in compose or stack files"
  fi
fi

# Optional: scan an exported image filesystem
if [[ -n "$IMAGE_DIR" ]]; then
  image_hits=$(grep -rIlE -- '-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----' "$IMAGE_DIR" 2>/dev/null \
    | while IFS= read -r f; do has_pem_key "$f" && echo "$f"; done || true)
  if [[ -n "$image_hits" ]]; then
    fail "private key material inside the image:"; echo "$image_hits" | sed 's/^/        /'
  else
    pass "no private key material inside the image"
  fi
fi

echo
if (( failures > 0 )); then
  echo "Security check failed: $failures problem(s)."
  exit 1
fi
echo "Security check passed."