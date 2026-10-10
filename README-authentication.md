# Authentication (users service)

The users service is the only service that issues tokens. It signs JWTs with an RSA private key (**RS256**). Other services, starting with the tasks API, verify those tokens with the matching **public key** and can never create one.

```
 client ──login──▶ users service ──signs with private.pem──▶ JWT
 client ──JWT────▶ tasks API ──verifies with public.pem──▶ 200 / 401 / 403
```

## Design decisions

| Decision | Why |
|---|---|
| **RS256 (asymmetric) instead of HS256** | With a shared secret, every service that verifies tokens could also forge them. With a key pair, only the users service holds the private key. A leaked tasks API config cannot mint tokens. |
| **Public key derived from the private key** | The users service needs to validate tokens as well as issue them. Deriving the public key at startup guarantees the two always match, and removes a second file and a second setting. |
| **Key loaded once at startup, from a file path** | A missing or malformed key stops the app immediately with a clear message, rather than failing on the first login. The key is never in code, the repo or the image. |
| **No default for `jwt.private-key-path`** | A misconfigured deployment must fail loudly. It must never start with the wrong key or no key. |
| **Issuer and audience are checked on every token** | A token signed with the right key but meant for another purpose is rejected. Both values come from configuration. |
| **30 seconds of clock skew allowed** | Absorbs small clock differences between services. A token expired by less than 30s is still accepted. |
| **The algorithm is pinned to RS256** | HS256 tokens (keyed with the public key bytes, the classic algorithm-confusion attack) and unsigned `alg: none` tokens are rejected. Both are covered by tests. |
| **Only `ROLE_*` roles are read from the token** | Anything else in the `roles` claim is ignored. A malformed or missing claim means no authorities, never an error. Spring Security's internal `FACTOR_PASSWORD` authority is deliberately excluded from tokens. |
| **Stateless sessions, CSRF disabled** | The API uses bearer tokens and never sets a session cookie, so there is nothing for a cross-site request to hijack. |
| **Every 401 and 403 uses the app's error format** | The entry point passes the failure to `GlobalExceptionHandler`, so clients see one consistent JSON shape. A 401 carries `WWW-Authenticate: Bearer`. |

## Token format

| Claim | Value |
|---|---|
| header `alg` | `RS256` |
| `iss` | `jwt.issuer` (default `user-service`) |
| `aud` | `jwt.audience` (default `taskflow-api`) |
| `sub` | the username |
| `iat`, `exp` | issue and expiry time. Lifetime is `jwt.expiration-ms` (default 1 hour). |
| `roles` | a list of strings, each starting with `ROLE_` (e.g. `["ROLE_ADMIN"]`) |

A token is rejected for any of these reasons:

| Reason | Cause |
|---|---|
| `EXPIRED` | past `exp` plus the 30s skew |
| `BAD_SIGNATURE` | signed with a different key, or the payload was changed |
| `MALFORMED` | not a valid JWT, or any other validation failure (unsupported algorithm, missing subject or expiry, wrong issuer or audience) |
| `EMPTY` | the token is blank |

Tokens cannot be revoked. Keep the lifetime short, and handle disabled users and logout on the users-service side.

## Access rules

| Endpoint | Rule |
|---|---|
| `POST /auth/login` | public |
| `POST /auth/validate` | admin only |
| `GET /api/users`, create and delete users | admin only |
| `GET /api/users/{id}` | admin, or the user reading their own profile |

An unauthenticated or invalid request gets a 401. An authenticated user without permission gets a 403.

## Configuration

| Property | Environment variable | Default |
|---|---|---|
| `jwt.private-key-path` | `JWT_PRIVATE_KEY_PATH` | none (required) |
| `jwt.expiration-ms` | `JWT_EXPIRATION_MS` | `3600000` |
| `jwt.issuer` | `JWT_ISSUER` | `user-service` |
| `jwt.audience` | `JWT_AUDIENCE` | `taskflow-api` |

The tasks API must use **exactly the same issuer and audience**. If they differ, every token is rejected with a 401 that looks like a signature problem.

## Keys

### Generate a key pair

```bash
mkdir -p ~/.taskflow/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ~/.taskflow/keys/private.pem
openssl rsa -pubout -in ~/.taskflow/keys/private.pem -out ~/.taskflow/keys/public.pem
chmod 600 ~/.taskflow/keys/private.pem
```

- The private key must be in **PKCS#8** format (the first line is `-----BEGIN PRIVATE KEY-----`), which is what `genpkey` produces. A key beginning `-----BEGIN RSA PRIVATE KEY-----` is rejected at startup. Convert it with `openssl pkcs8 -topk8 -nocrypt -in old.pem -out private.pem`.
- The private key stays outside the project folder, and `*.pem` is in `.gitignore`.
- `public.pem` is not secret. It is the only key file the tasks API needs.
- If a private key was ever committed or shared, regenerate it. Deleting the file from the repo is not enough.

### Run locally (`mvn`)

Set the variable in your shell or IDE run configuration:

```bash
export JWT_PRIVATE_KEY_PATH=$HOME/.taskflow/keys/private.pem
```

Environment variables set in a Docker Compose file or `.env` are not visible to a plain `mvn` run. To avoid exporting every time, put the path in a git-ignored `config/application.properties`, which Spring Boot loads automatically from the working directory.

### Run with Docker Compose

The key is mounted as a Compose secret, so it never enters the image:

```yaml
user-service:
  environment:
    - JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private_key   # path inside the container
  secrets:
    - jwt_private_key

secrets:
  jwt_private_key:
    file: ${JWT_PRIVATE_KEY_FILE:-${HOME}/.taskflow/keys/private.pem}   # path on the host
```

- The host path is the default location, and `JWT_PRIVATE_KEY_FILE` overrides it. Compose does not expand `~`, so use `${HOME}`.
- The container runs as a non-root user (`spring`). A key with mode `600` owned by your host user is not readable by that user, and the app fails with `AccessDeniedException`. Fix it with either:
  - `chmod 644` on a **dev-only** key (never reuse that key elsewhere), or
  - `user: "${LOCAL_UID:-1000}:${LOCAL_GID:-1000}"` on the service, with `LOCAL_UID` and `LOCAL_GID` set to your `id -u` and `id -g`.
- Do not set `JWT_SECRET` or `JWT_PUBLIC_KEY_PATH`. The service uses neither.
- The published port mapping must match `APP_PORT`, because `server.port` follows that variable.

## Testing

| Test | What it covers |
|---|---|
| `JwtServiceTest` | token issuing and validation: round trip, role filtering, and the rejection cases (expired, wrong key, tampered payload, wrong issuer or audience, HS256, unsigned, missing subject, garbage, empty) |
| `PemKeyLoaderTest` | key loading, including bad input and PKCS#1 keys, and public-key derivation |
| `UsersEndToEndTest` | the full HTTP flow through the real filter chain: login, access, rejection and role rules |
| `smoke-test.sh` | the same checks against the real running stack, plus signature verification with `openssl` and an optional restart check |

Tests never use your real keys. `TestJwtKeys` generates a throwaway RSA pair per run and registers the properties through `@DynamicPropertySource`. Every test class that starts the Spring context needs the same `@DynamicPropertySource`.

Run the unit and integration tests with `mvn clean test`. Run the smoke test from the project root, on the host:

```bash
./smoke-test.sh --up --restart
```

It reads `.env` and `~/.taskflow/keys/`, starts a fresh stack, and exits non-zero if any check fails. Run it after any change to security config, keys or Docker setup.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Could not resolve placeholder 'jwt.private-key-path'` | `JWT_PRIVATE_KEY_PATH` is not set in the environment that started the app, or the test lacks `@DynamicPropertySource` |
| `Could not load private key ... AccessDeniedException` | the container user cannot read the mounted key (see the Docker permissions fix above) |
| `Could not load private key ... NoSuchFileException` | wrong path, or the key is not mounted into the container |
| `Could not load private key` with a `BEGIN RSA PRIVATE KEY` file | the key is PKCS#1. Convert it to PKCS#8. |
| `Unable to determine Dialect without JDBC metadata` | the database is unreachable (not running, wrong credentials, or the database does not exist) |
| No response on `localhost:8080` | the port mapping does not match `APP_PORT`. Check the log line `Tomcat started on port ...`. |
| Every token rejected with 401 after a change | the issuer or audience differs between services, or the signing key and the verifying public key no longer pair |

## Known limitations

- **Revocation:** a token stays valid until it expires. There is no logout or deny list.
- **Key rotation:** there is one static key pair. Rotating means replacing the key and restarting every service, and existing tokens stop working. Supporting rotation needs a `kid` header and a JWKS endpoint.
- **Seeded admin and schema:** the default admin credentials are for development only, and `spring.jpa.hibernate.ddl-auto=create` recreates all tables on every start.
- **Tasks API:** not yet integrated. It will need the public key, the same issuer and audience, and no token-issuing code.
