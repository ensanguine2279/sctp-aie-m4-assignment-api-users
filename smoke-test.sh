#!/usr/bin/env bash
#
# Smoke test for the users service (RS256 JWT).
#
# Usage:
#   ./smoke-test.sh                 # test a service that is already running
#   ./smoke-test.sh --up            # docker compose down -v, up --build -d, then test
#   ./smoke-test.sh --up --restart  # ...and also check tokens survive a service restart
#
# Settings (environment variables, all optional):
#   BASE_URL            default http://localhost:8022
#   ENV_FILE            default .env (read for ADMIN_*_ENV and JWT_*_ENV values)
#   ADMIN_USERNAME / ADMIN_PASSWORD   override the values from .env
#   KEY_DIR             default ~/.taskflow/keys (private.pem and public.pem live here)
#   PRIVATE_KEY_FILE / PUBLIC_KEY_FILE   override individual key files
#   SERVICE_NAME        compose service name, default user-service
#   WAIT_SECS           how long to wait for the service to answer, default 120
#
# Needs: bash, curl, openssl, base64, od. Exit code is 0 only if every check passes
#
# Against a deployed service (for example Railway):
#   BASE_URL=https://your-service.up.railway.app ADMIN_USERNAME=... ADMIN_PASSWORD=... \
#   PUBLIC_KEY_FILE=/path/to/production-public.pem JWT_ISSUER=... JWT_AUDIENCE=... WAIT_SECS=240 \
#   ./smoke-test.sh
# - --up and --restart control a LOCAL docker compose stack, so they are refused for a non-local BASE_URL.
# - The checks that sign tokens with the real private key run only if PRIVATE_KEY_FILE exists. Do not point it at
#   your development key when testing production: it is a different key, so those checks would fail.
# - The run creates one throwaway user and deletes it again.
#
# Assumptions about the API (taken from UsersEndToEndTest): POST /auth/login returns
# {"token": ...}; POST /api/users takes username/password/name/role and returns an "id";
# GET /api/users is admin-only; /auth/validate is admin-only. Tokens carry the user's
# database id as a numeric "uid" claim, and /auth/validate returns it as claims.userId.

set -uo pipefail

BASE_URL=${BASE_URL:-http://localhost:8022}
ENV_FILE=${ENV_FILE:-.env}
KEY_DIR=${KEY_DIR:-$HOME/.taskflow/keys}
PRIVATE_KEY_FILE=${PRIVATE_KEY_FILE:-$KEY_DIR/private.pem}
PUBLIC_KEY_FILE=${PUBLIC_KEY_FILE:-$KEY_DIR/public.pem}
SERVICE_NAME=${SERVICE_NAME:-user-service}
WAIT_SECS=${WAIT_SECS:-120}

PASS=0
FAIL=0
SKIP=0
CODE=""
BODY=""
TMP=""
CREATED_ID=""
ADMIN_TOKEN=""

# is_local_url URL -> exit 0 for localhost, 127.0.0.1 and [::1]
is_local_url() {
    [[ $1 =~ ^https?://(localhost|127\.0\.0\.1|\[::1\])([:/]|$) ]]
}

# ---------- output helpers ----------

ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [[ -n ${2:-} ]] && printf '       %s\n' "$2"; return 0; }
skip() { SKIP=$((SKIP + 1)); printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
section() { printf '\n== %s ==\n' "$1"; }

expect_code() { # description expected-code
    if [[ $CODE == "$2" ]]; then ok "$1 (HTTP $CODE)"; else bad "$1" "expected HTTP $2, got $CODE: ${BODY:0:200}"; fi
}

expect_2xx() { # description
    if [[ $CODE == 2* ]]; then ok "$1 (HTTP $CODE)"; else bad "$1" "expected HTTP 2xx, got $CODE: ${BODY:0:200}"; fi
}

expect_www_authenticate() { # description
    if grep -qi '^www-authenticate: *Bearer' "$TMP/headers"; then ok "$1"; else bad "$1" "WWW-Authenticate: Bearer header missing"; fi
}

# ---------- http helper ----------

# request METHOD PATH [curl args...]  ->  sets CODE and BODY, headers saved in $TMP/headers
request() {
    local method=$1 path=$2
    shift 2
    CODE=$(curl -s -o "$TMP/body" -D "$TMP/headers" -w '%{http_code}' -X "$method" "$BASE_URL$path" "$@" || true)
    BODY=$(cat "$TMP/body" 2>/dev/null || true)
}

auth() { printf 'Authorization: %s' "$1"; }

# ---------- jwt helpers ----------

b64url_decode() {
    local s=$1
    s=${s//-/+}
    s=${s//_//}
    case $(( ${#s} % 4 )) in
        2) s="$s==" ;;
        3) s="$s=" ;;
    esac
    printf '%s' "$s" | base64 -d 2>/dev/null
}

b64url_encode() {
    printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

jwt_part() { # token index(1=header 2=payload 3=signature)
    printf '%s' "$1" | cut -d. -f"$2"
}

# verify_rs256 TOKEN PUBLIC_KEY_FILE  -> exit 0 if the RS256 signature is valid
verify_rs256() {
    local token=$1 pub=$2 h p s
    h=$(jwt_part "$token" 1)
    p=$(jwt_part "$token" 2)
    s=$(jwt_part "$token" 3)
    b64url_decode "$s" > "$TMP/sig.bin"
    printf '%s' "$h.$p" | openssl dgst -sha256 -verify "$pub" -signature "$TMP/sig.bin" > /dev/null 2>&1
}

# forge_hs256 PUBLIC_KEY_FILE PAYLOAD_B64  -> token signed with HMAC using the public key bytes
forge_hs256() {
    local pub=$1 payload=$2 header hexkey sig
    header=$(b64url_encode '{"alg":"HS256","typ":"JWT"}')
    hexkey=$(openssl pkey -pubin -in "$pub" -outform DER 2> /dev/null | od -An -v -tx1 | tr -d ' \n')
    sig=$(printf '%s' "$header.$payload" \
        | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$hexkey" -binary 2> /dev/null \
        | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    printf '%s.%s.%s' "$header" "$payload" "$sig"
}

# forge_rs256 PRIVATE_KEY_FILE PAYLOAD_JSON -> a token with a VALID signature and the given claims
forge_rs256() {
    local key=$1 payload_json=$2 header payload sig
    header=$(b64url_encode '{"alg":"RS256","typ":"JWT"}')
    payload=$(b64url_encode "$payload_json")
    sig=$(printf '%s' "$header.$payload" \
        | openssl dgst -sha256 -sign "$key" -binary 2> /dev/null \
        | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    printf '%s.%s.%s' "$header" "$payload" "$sig"
}

# signed_admin_token ISSUER AUDIENCE UID_FRAGMENT -> admin token signed with the real key.
# UID_FRAGMENT is spliced into the JSON: ',"uid":1' for a good one, '' to omit it, ',"uid":"1"' for a string.
signed_admin_token() {
    local now json
    now=$(date +%s)
    json=$(printf '{"iss":"%s","aud":["%s"],"sub":"%s","iat":%s,"exp":%s,"roles":["ROLE_ADMIN"]%s}' \
        "$1" "$2" "$ADMIN_USERNAME" "$now" "$((now + 600))" "$3")
    forge_rs256 "$PRIVATE_KEY_FILE" "$json"
}

# tamper_signature TOKEN -> same token with one character changed in the middle of the signature
tamper_signature() {
    local h p s c
    h=$(jwt_part "$1" 1)
    p=$(jwt_part "$1" 2)
    s=$(jwt_part "$1" 3)
    c=A
    [[ ${s:5:1} == A ]] && c=B
    printf '%s.%s.%s' "$h" "$p" "${s:0:5}${c}${s:6}"
}

# login USERNAME PASSWORD -> sets LOGIN_TOKEN (empty on failure); CODE and BODY stay available
# (not run in a subshell on purpose, so a failed login can still be reported)
LOGIN_TOKEN=""
login() {
    request POST /auth/login -H 'Content-Type: application/json' \
        -d "{\"username\":\"$1\",\"password\":\"$2\"}"
    LOGIN_TOKEN=$(printf '%s' "$BODY" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
}

# ---------- setup ----------

env_value() { # KEY -> value from the env file, or empty
    [[ -f $ENV_FILE ]] || return 0
    grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed -E "s/^[\"']|[\"']\$//g"
}

wait_ready() {
    local waited=0 c
    printf 'Waiting for %s (up to %ss)...' "$BASE_URL" "$WAIT_SECS"
    while (( waited < WAIT_SECS )); do
        c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/api/users" || true)
        if [[ $c != 000 && $c != 502 && $c != 503 ]]; then
            printf ' ready (HTTP %s)\n' "$c"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
        printf '.'
    done
    printf ' timed out\n'
    return 1
}

cleanup() {
    if [[ -n $CREATED_ID && -n $ADMIN_TOKEN && -d $TMP ]]; then
        curl -s -o /dev/null -X DELETE "$BASE_URL/api/users/$CREATED_ID" -H "$(auth "Bearer $ADMIN_TOKEN")" || true
    fi
    [[ -n $TMP ]] && rm -rf "$TMP"
}

# ---------- checks ----------

check_token_contents() {
    section "Token contents"
    local header payload now exp
    header=$(b64url_decode "$(jwt_part "$ADMIN_TOKEN" 1)")
    payload=$(b64url_decode "$(jwt_part "$ADMIN_TOKEN" 2)")

    [[ $(printf '%s' "$ADMIN_TOKEN" | tr -cd '.' | wc -c) -eq 2 ]] && ok "token has three parts" || bad "token has three parts"
    [[ $header == *'"alg":"RS256"'* ]] && ok "header alg is RS256" || bad "header alg is RS256" "header: $header"
    [[ $payload == *'"roles":["ROLE_ADMIN"]'* ]] && ok "roles claim is exactly [ROLE_ADMIN]" || bad "roles claim is exactly [ROLE_ADMIN]" "payload: $payload"
    [[ $payload == *"\"sub\":\"$ADMIN_USERNAME\""* ]] && ok "subject is $ADMIN_USERNAME" || bad "subject is $ADMIN_USERNAME" "payload: $payload"
    local uid_re='"uid":([0-9]+)[,}]'
    if [[ $payload =~ $uid_re && ${BASH_REMATCH[1]} -gt 0 ]]; then
        ok "uid claim is a positive JSON number (${BASH_REMATCH[1]})"
    else
        bad "uid claim is a positive JSON number" "payload: $payload"
    fi

    local expected_iss expected_aud
    expected_iss=${JWT_ISSUER:-$(env_value JWT_ISSUER_ENV)}
    expected_aud=${JWT_AUDIENCE:-$(env_value JWT_AUDIENCE_ENV)}
    if [[ -n $expected_iss ]]; then
        [[ $payload == *"\"iss\":\"$expected_iss\""* ]] && ok "issuer is $expected_iss" || bad "issuer is $expected_iss" "payload: $payload"
    else
        skip "issuer (set JWT_ISSUER or JWT_ISSUER_ENV in $ENV_FILE to check it)"
    fi
    if [[ -n $expected_aud ]]; then
        [[ $payload == *"\"$expected_aud\""* && $payload == *'"aud"'* ]] && ok "audience is $expected_aud" || bad "audience is $expected_aud" "payload: $payload"
    else
        skip "audience (set JWT_AUDIENCE or JWT_AUDIENCE_ENV in $ENV_FILE to check it)"
    fi

    now=$(date +%s)
    exp=$(printf '%s' "$payload" | sed -n 's/.*"exp":\([0-9]*\).*/\1/p')
    if [[ -n $exp && $exp -gt $now ]]; then ok "token expires in the future ($(( (exp - now) / 60 )) min left)"; else bad "token expires in the future" "exp=$exp now=$now"; fi
}

check_keys() {
    section "Keys"
    if [[ -f $PUBLIC_KEY_FILE ]]; then
        if verify_rs256 "$ADMIN_TOKEN" "$PUBLIC_KEY_FILE"; then
            ok "signature verifies against $PUBLIC_KEY_FILE"
        else
            bad "signature verifies against $PUBLIC_KEY_FILE" "the service is signing with a key that does not pair with this public key (for a deployed service, PUBLIC_KEY_FILE must be its production public key)"
        fi
    else
        skip "signature check (no public key at $PUBLIC_KEY_FILE)"
    fi

    if [[ -f $PRIVATE_KEY_FILE && -f $PUBLIC_KEY_FILE ]]; then
        if openssl rsa -in "$PRIVATE_KEY_FILE" -pubout 2> /dev/null | diff -q - "$PUBLIC_KEY_FILE" > /dev/null; then
            ok "public.pem is the pair of private.pem"
        else
            bad "public.pem is the pair of private.pem"
        fi
    else
        skip "key pair match (need both private.pem and public.pem)"
    fi
}

check_access() {
    section "Access with the admin token"
    request GET /api/users -H "$(auth "Bearer $ADMIN_TOKEN")"
    expect_code "valid token can list users" 200

    request GET /api/users -H "$(auth "bearer $ADMIN_TOKEN")"
    expect_code "lowercase 'bearer' scheme is accepted" 200

    request POST /auth/validate -H "$(auth "Bearer $ADMIN_TOKEN")" -H 'Content-Type: application/json' \
        -d "{\"token\":\"$ADMIN_TOKEN\"}"
    expect_code "admin can call /auth/validate" 200
    if printf '%s' "$BODY" | grep -Eq '"valid"[[:space:]]*:[[:space:]]*true'; then
        ok "/auth/validate reports valid:true"
    else
        bad "/auth/validate reports valid:true" "${BODY:0:200}"
    fi
    if printf '%s' "$BODY" | grep -Eq '"userId"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
        ok "/auth/validate returns claims.userId"
    else
        bad "/auth/validate returns claims.userId" "${BODY:0:200}"
    fi
}

check_rejections() {
    section "Rejected requests"
    request GET /api/users
    expect_code "no Authorization header" 401
    expect_www_authenticate "401 carries WWW-Authenticate: Bearer"

    request GET /api/users -H "$(auth "Bearer $(tamper_signature "$ADMIN_TOKEN")")"
    expect_code "tampered signature" 401

    request GET /api/users -H "$(auth 'Bearer not.a.jwt')"
    expect_code "garbage token" 401

    request GET /api/users -H "$(auth 'Basic YWRtaW46cGFzcw==')"
    expect_code "non-Bearer scheme (Basic)" 401

    local h p
    h=$(b64url_encode '{"alg":"none","typ":"JWT"}')
    p=$(jwt_part "$ADMIN_TOKEN" 2)
    request GET /api/users -H "$(auth "Bearer $h.$p.")"
    expect_code "unsigned token (alg none) with valid claims" 401

    if [[ -f $PUBLIC_KEY_FILE ]]; then
        request GET /api/users -H "$(auth "Bearer $(forge_hs256 "$PUBLIC_KEY_FILE" "$p")")"
        expect_code "HS256 token keyed with the public key (algorithm confusion)" 401
    else
        skip "algorithm-confusion check (no public key at $PUBLIC_KEY_FILE)"
    fi

    local iss aud
    iss=${JWT_ISSUER:-$(env_value JWT_ISSUER_ENV)}
    aud=${JWT_AUDIENCE:-$(env_value JWT_AUDIENCE_ENV)}
    if [[ -f $PRIVATE_KEY_FILE && -n $iss && -n $aud ]]; then
        # Control first: proves the forged-token helper works, so the 401s below are about the uid.
        request GET /api/users -H "$(auth "Bearer $(signed_admin_token "$iss" "$aud" ',"uid":1')")"
        expect_code "control: correctly signed token with a uid is accepted" 200
        request GET /api/users -H "$(auth "Bearer $(signed_admin_token "$iss" "$aud" '')")"
        expect_code "correctly signed token with no uid claim" 401
        request GET /api/users -H "$(auth "Bearer $(signed_admin_token "$iss" "$aud" ',"uid":"1"')")"
        expect_code "correctly signed token with a string uid" 401
        request GET /api/users -H "$(auth "Bearer $(signed_admin_token "$iss" "$aud" ',"uid":0')")"
        expect_code "correctly signed token with uid 0" 401
    else
        skip "uid rejection checks (need private.pem and JWT_ISSUER_ENV / JWT_AUDIENCE_ENV in $ENV_FILE)"
    fi
}

check_roles() {
    section "Roles"
    local name="smoke$(date +%s)" password="Smoke-pass-1" user_token

    request POST /api/users -H "$(auth "Bearer $ADMIN_TOKEN")" -H 'Content-Type: application/json' \
        -d "{\"username\":\"$name\",\"password\":\"$password\",\"name\":\"Smoke Test\",\"role\":\"USER\"}"
    expect_2xx "admin can create a USER account"
    CREATED_ID=$(printf '%s' "$BODY" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p')
    if [[ -z $CREATED_ID ]]; then
        bad "create response contains an id" "${BODY:0:200}"
        return
    fi

    login "$name" "$password"
    user_token=$LOGIN_TOKEN
    if [[ -z $user_token ]]; then
        bad "new user can log in" "${BODY:0:200}"
        return
    fi
    ok "new user can log in"

    local payload
    payload=$(b64url_decode "$(jwt_part "$user_token" 2)")
    [[ $payload == *'"roles":["ROLE_USER"]'* ]] && ok "user token roles are [ROLE_USER]" || bad "user token roles are [ROLE_USER]" "payload: $payload"

    if [[ $payload == *"\"uid\":$CREATED_ID,"* || $payload == *"\"uid\":$CREATED_ID}"* ]]; then
        ok "user token uid is the new user's id ($CREATED_ID)"
    else
        bad "user token uid is the new user's id ($CREATED_ID)" "payload: $payload"
    fi

    request GET /api/users -H "$(auth "Bearer $user_token")"
    expect_code "USER token cannot list all users" 403

    request GET "/api/users/$CREATED_ID" -H "$(auth "Bearer $user_token")"
    expect_code "USER token can read its own profile" 200

    request POST /auth/validate -H "$(auth "Bearer $user_token")" -H 'Content-Type: application/json' \
        -d "{\"token\":\"$user_token\"}"
    expect_code "USER token cannot call /auth/validate" 403

    request DELETE "/api/users/$CREATED_ID" -H "$(auth "Bearer $ADMIN_TOKEN")"
    expect_2xx "admin can delete the smoke-test user"
    CREATED_ID=""
}

check_restart() {
    section "Restart persistence"
    if ! command -v docker > /dev/null; then
        skip "restart check (docker not found)"
        return
    fi
    docker compose restart "$SERVICE_NAME" > /dev/null 2>&1 || { bad "docker compose restart $SERVICE_NAME"; return; }
    wait_ready || { bad "service came back after restart"; return; }
    request GET /api/users -H "$(auth "Bearer $ADMIN_TOKEN")"
    expect_code "token issued before the restart is still accepted" 200
}

# ---------- main ----------

main() {
    local do_up=0 do_restart=0 arg
    for arg in "$@"; do
        case $arg in
            --up) do_up=1 ;;
            --restart) do_restart=1 ;;
            -h|--help) awk 'NR > 1 && /^#/ { print; next } NR > 1 { exit }' "$0"; return 0 ;;
            *) echo "Unknown option: $arg (try --help)" >&2; return 2 ;;
        esac
    done

    if (( do_up || do_restart )) && ! is_local_url "$BASE_URL"; then
        echo "--up and --restart manage the local docker compose stack, but BASE_URL is $BASE_URL." >&2
        echo "Run without them against a deployed service, and redeploy from the platform if you want a restart check." >&2
        return 2
    fi

    for tool in curl openssl base64 od; do
        command -v "$tool" > /dev/null || { echo "Missing required tool: $tool" >&2; return 2; }
    done

    ADMIN_USERNAME=${ADMIN_USERNAME:-$(env_value ADMIN_USERNAME_ENV)}
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-$(env_value ADMIN_PASSWORD_ENV)}
    if [[ -z $ADMIN_USERNAME || -z $ADMIN_PASSWORD ]]; then
        echo "Set ADMIN_USERNAME and ADMIN_PASSWORD, or provide ADMIN_USERNAME_ENV and ADMIN_PASSWORD_ENV in $ENV_FILE" >&2
        return 2
    fi

    TMP=$(mktemp -d)
    trap cleanup EXIT

    if (( do_up )); then
        section "Starting the stack"
        docker compose down -v && docker compose up --build -d || { echo "docker compose failed" >&2; return 1; }
    fi

    section "Startup"
    if wait_ready; then ok "service answers on $BASE_URL"; else bad "service answers on $BASE_URL"; return 1; fi

    section "Login"
    login "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
    ADMIN_TOKEN=$LOGIN_TOKEN
    if [[ -z $ADMIN_TOKEN ]]; then
        bad "admin can log in" "HTTP $CODE: ${BODY:0:200}"
        printf '\nCannot continue without a token.\n'
        return 1
    fi
    ok "admin can log in"

    check_token_contents
    check_keys
    check_access
    check_rejections
    check_roles
    (( do_restart )) && check_restart

    printf '\n== Summary ==\n  passed: %d   failed: %d   skipped: %d\n' "$PASS" "$FAIL" "$SKIP"
    (( FAIL == 0 ))
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi