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
| **Key loaded once at startup, from a file or an environment variable** | A missing, malformed or too-weak key stops the app immediately with a clear message, rather than failing on the first login. The key is never in code, the repo or the image. A file path suits Docker Compose. `JWT_PRIVATE_KEY_BASE64` suits platforms that cannot mount files. |
| **No default key** | One of `jwt.private-key-base64` and `jwt.private-key-path` must be set, otherwise startup fails. If both are set, the variable wins, and a broken variable never falls back to the path. A misconfigured deployment must fail loudly. It must never start with the wrong key or no key. |
| **Issuer and audience are checked on every token** | A token signed with the right key but meant for another purpose is rejected. Both values come from configuration. |
| **30 seconds of clock skew allowed** | Absorbs small clock differences between services. A token expired by less than 30s is still accepted. |
| **The algorithm is pinned to RS256** | HS256 tokens (keyed with the public key bytes, the classic algorithm-confusion attack) and unsigned `alg: none` tokens are rejected. Both are covered by tests. |
| **Only `ROLE_*` roles are read from the token** | Anything else in the `roles` claim is ignored. A malformed or missing claim means no authorities, never an error. Spring Security's internal `FACTOR_PASSWORD` authority is deliberately excluded from tokens. |
| **Self-service checks use the id in the token** | `UserSecurity.isSelf` compares the caller's `uid` (carried by the request principal) with the id in the path, so there is no database lookup, and a username that happens to match is never enough. |
| **Stateless sessions, CSRF disabled** | The API uses bearer tokens and never sets a session cookie, so there is nothing for a cross-site request to hijack. |
| **Every 401 and 403 uses the app's error format** | The entry point passes the failure to `GlobalExceptionHandler`, so clients see one consistent JSON shape. A 401 carries `WWW-Authenticate: Bearer`. |

## Token format

| Claim | Value |
|---|---|
| header `alg` | `RS256` |
| `iss` | `jwt.issuer` (default `user-service`) |
| `aud` | `jwt.audience` (default `taskflow-api`) |
| `sub` | the username |
| `uid` | the user's database id, a positive JSON number. Required: a token without a valid `uid` is rejected by both services. |
| `iat`, `exp` | issue and expiry time. Lifetime is `jwt.expiration-ms` (default 1 hour). |
| `roles` | a list of strings, each starting with `ROLE_` (e.g. `["ROLE_ADMIN"]`) |

A token is rejected for any of these reasons:

| Reason | Cause |
|---|---|
| `EXPIRED` | past `exp` plus the 30s skew |
| `BAD_SIGNATURE` | signed with a different key, or the payload was changed |
| `MALFORMED` | not a valid JWT, or any other validation failure (unsupported algorithm, missing subject, expiry or valid `uid`, wrong issuer or audience) |
| `EMPTY` | the token is blank |

Tokens cannot be revoked. Keep the lifetime short, and handle disabled users and logout on the users-service side.

## Access rules

| Endpoint | Rule |
|---|---|
| `POST /auth/login` | public |
| `POST /auth/validate` | admin only |
| `GET /api/users`, create and delete users | admin only |
| `GET /api/users/{id}` | admin, or the user reading their own profile (matched by the `uid` in the token, with no database lookup) |

An unauthenticated or invalid request gets a 401. An authenticated user without permission gets a 403.

## Configuration

| Property | Environment variable | Default |
|---|---|---|
| `jwt.private-key-base64` | `JWT_PRIVATE_KEY_BASE64` | none. The key itself, base64-encoded or as a raw PEM. Wins over the path. |
| `jwt.private-key-path` | `JWT_PRIVATE_KEY_PATH` | none. A key file. One of the two key settings is required. |
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
- The key must be RSA of at least 2048 bits. A weaker key stops the app at startup, not on the first login.
- The private key stays outside the project folder, and `*.pem` is in `.gitignore`.
- `public.pem` is not secret. It is the only key file the tasks API needs.
- If a private key was ever committed or shared, regenerate it. Deleting the file from the repo is not enough.

### Run locally (`mvn`)

Set the variable in your shell or IDE run configuration:

```bash
export JWT_PRIVATE_KEY_PATH=$HOME/.taskflow/keys/private.pem
```

Environment variables set in a Docker Compose file or `.env` are not visible to a plain `mvn` run. To avoid exporting every time, put the path in a git-ignored `config/application.properties`, which Spring Boot loads automatically from the working directory. `JWT_PRIVATE_KEY_BASE64` works for `mvn` runs too, but it takes precedence over the path, so unset it when you want the file to apply.

### Run on a platform that only supports environment variables (for example Railway)

Set `JWT_PRIVATE_KEY_BASE64` to the whole private key file, base64-encoded on one line:

```bash
base64 -w0 private.pem                 # Linux
base64 -i private.pem | tr -d '\n'     # macOS
```

The raw PEM text is accepted too, as are line breaks, surrounding whitespace and literal `\n` sequences, which dashboards sometimes produce.

- `JWT_PRIVATE_KEY_BASE64` wins over `JWT_PRIVATE_KEY_PATH` when both are set. A broken value stops the app at startup: it does not fall back to the path.
- The key must be an unencrypted **PKCS#8** RSA key of at least 2048 bits. A `BEGIN RSA PRIVATE KEY`, encrypted, EC or public key is rejected with a message that names what was found.
- Generate a **new** key pair for production. Never upload the development key, and give the public half (`public.pem`) to the tasks API.
- Treat the variable as a secret: mark it sealed or hidden if the platform offers that, never print the environment in logs, and do not expose an endpoint that dumps it. Regenerate the key if it was ever pasted into a chat, a screenshot or a commit.
- The `jwt.issuer` and `jwt.audience` values must still match the tasks API.

Other settings a deployment needs (names as in `docker-compose.yml`):

- **Database:** map the platform's database host, port, name, user and password to `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` and `DB_PASSWORD`. These are the platform's values, not the Docker Compose ones (`user-db` and 5432).
- **Port:** the platform tells the container which port to listen on (Railway sets `PORT`), and the application listens on `APP_PORT`, so set `APP_PORT` to that same value.
- **Seeded admin:** change the default admin username and password before the first start. The development defaults are public.
- **Schema:** `spring.jpa.hibernate.ddl-auto=create` recreates all tables, and reseeds the admin, on every start. On a platform that restarts and redeploys services, that wipes the users. Ids restart from 1, so tokens issued earlier can point at different people, and tasks that the tasks API stores against the old ids no longer match the right users. Change it to `update`, or use a migration tool, before keeping real data.
- **Tasks API:** it needs the `public.pem` of the same key pair, and the same issuer and audience.
- **Check it:** run `smoke-test.sh` against the deployed URL (see Testing).

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
- Do not also set `JWT_PRIVATE_KEY_BASE64` in `.env`. It wins over the mounted file, so Compose would silently use that key instead.
- The published port mapping must match `APP_PORT`, because `server.port` follows that variable.

## Testing

| Test | What it covers |
|---|---|
| `JwtServiceTest` | token issuing and validation: round trip, `uid` and role filtering, the rejection cases (expired, wrong key, tampered payload, wrong issuer or audience, HS256, unsigned, missing subject, bad or missing `uid`, garbage, empty), and loading the key from a file or from `JWT_PRIVATE_KEY_BASE64` in the formats people paste (base64, wrapped base64, raw PEM, surrounding whitespace, literal `\n`), with the rejection of PKCS#1, public, encrypted, non-RSA and weak keys, precedence, no fallback from a broken variable, and that errors never contain the key |
| `JwtServiceWiringTest` | Spring injects the two key properties: an environment variable named `JWT_PRIVATE_KEY_BASE64` reaches the property, the variable wins over a path, and having neither source stops startup |
| `PemKeyLoaderTest` | key loading from a file, including bad input and PKCS#1 keys, and public-key derivation |
| `JwtAuthFilterTest` | the filter on its own: no header, non-Bearer scheme, valid and invalid tokens, and that the principal carries the username and the user id |
| `DatabaseUserDetailsServiceTest` | the login principal: the stored password hash is passed through untouched, the role becomes a `ROLE_` authority, the principal carries the database id, and the full login path with BCrypt |
| `UserSecurityTest` | `isSelf` compares ids from the token and refuses when in doubt |
| `AuthControllerTest`, `UserControllerTest` | the web layer with the real security configuration and a mocked `JwtService`: statuses, error bodies, role rules, and that login issues the token with the user's id |
| `UsersEndToEndTest` | the full HTTP flow through the real filter chain with the key as a file: login, access, rejection and role rules |
| `UsersBase64KeyEndToEndTest` | the same application with the key supplied only as `jwt.private-key-base64`: the token verifies with the right key and carries the user's id, the role rules and self check work, and wrong-key and tampered tokens are rejected |
| `UsersBase64KeyPrecedenceEndToEndTest` | both sources set, with different keys: the variable's key signs the tokens |
| `smoke-test.sh` | the same checks against a real running stack, plus signature verification with `openssl`, the `uid` rules, and an optional restart check |

Tests never use your real keys. `TestJwtKeys` generates a throwaway RSA pair per run and registers the properties through `@DynamicPropertySource`. Every test class that starts the Spring context needs the same `@DynamicPropertySource`. It also sets `jwt.private-key-base64` to an empty string, so a `JWT_PRIVATE_KEY_BASE64` exported in your shell (for example while trying out a deployment) cannot replace the test key.

Run the unit and integration tests with `mvn clean test`. Run the smoke test from the project root, on the host:

```bash
./smoke-test.sh --up --restart
```

It reads `.env` and `~/.taskflow/keys/`, starts a fresh stack, and exits non-zero if any check fails. Run it after any change to security config, keys or Docker setup.

Against a deployed service (for example Railway), leave out `--up` and `--restart`, which manage the local Compose stack and are refused for a non-local URL:

```bash
BASE_URL=https://your-service.up.railway.app \
ADMIN_USERNAME=... ADMIN_PASSWORD=... \
PUBLIC_KEY_FILE=/path/to/production-public.pem \
JWT_ISSUER=... JWT_AUDIENCE=... WAIT_SECS=240 \
./smoke-test.sh
```

The check that matters most there is "signature verifies against the public key": it proves the deployed service signs with the key whose public half you gave the tasks API. The checks that sign tokens with the private key are skipped unless `PRIVATE_KEY_FILE` exists, and that must not be your development key. The run creates one throwaway user and deletes it again.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Could not resolve placeholder 'jwt.private-key-path'` or `'jwt.private-key-base64'` | the property has no value in the environment that started the app (give it an empty default in `application.properties`), or the test lacks `@DynamicPropertySource` |
| `Neither 'jwt.private-key-base64' nor 'jwt.private-key-path' is configured` | both key settings are empty. Set one of them. |
| `Failed to load JWT private key from Base64 environment variable: expected an unencrypted PKCS#8 key ... but found '...'` | the value is a different kind of key (`RSA PRIVATE KEY`, `PUBLIC KEY`, `ENCRYPTED PRIVATE KEY`). Use an unencrypted PKCS#8 private key. |
| `Failed to load JWT private key from Base64 environment variable: the value is neither a PEM private key nor a base64-encoded one` | the variable holds something else, or a truncated value. Encode the whole PEM file on one line: `base64 -w0 private.pem`. |
| `The JWT private key must be an RSA key of at least 2048 bits` | a weaker or non-RSA key. Generate a new one with the command above. |
| `Token has no valid uid` | the token was issued before the `uid` claim existed, or by a service that does not add it. Log in again. |
| `Could not load private key ... AccessDeniedException` | the container user cannot read the mounted key (see the Docker permissions fix above) |
| `Could not load private key ... NoSuchFileException` | wrong path, or the key is not mounted into the container |
| `Could not load private key` with a `BEGIN RSA PRIVATE KEY` file | the key is PKCS#1. Convert it to PKCS#8. |
| `Unable to determine Dialect without JDBC metadata` | the database is unreachable (not running, wrong credentials, or the database does not exist) |
| No response on `localhost:8080` | the port mapping does not match `APP_PORT`. Check the log line `Tomcat started on port ...`. |
| Every token rejected with 401 after a change | the issuer or audience differs between services, or the signing key and the verifying public key no longer pair |

## Known limitations

- **Revocation:** a token stays valid until it expires. There is no logout or deny list.
- **Key rotation:** there is one static key pair. Rotating means replacing the key and restarting every service, and existing tokens stop working. Supporting rotation needs a `kid` header and a JWKS endpoint.
- **Seeded admin and schema:** the default admin credentials are for development only, and `spring.jpa.hibernate.ddl-auto=create` recreates all tables on every start. On a deployed service that wipes the users on each redeploy and restarts the ids from 1 (see the deployment notes above), so change it before keeping real data.
- **Tasks API:** integrated. It verifies these tokens with the public key only. See the tasks API's `AUTHENTICATION.md`.
- **Token claims:** the `uid` claim means tokens issued before it was added stop working. Users must log in again.