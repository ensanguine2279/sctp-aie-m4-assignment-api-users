# Module 4 Assignment - TaskFlow Users Service

A Spring Boot REST service that manages users and issues JWTs for the TaskFlow system. It handles registration by an admin, login, role-based access control and token inspection. The task APIs live in a separate project, which trusts the tokens this service issues.

## Features

- Stateless authentication with JWTs signed with RS256 (an RSA key pair), with the user's roles inside the token
- Tokens carry an issuer and an audience that consumers check, and only this service can create them
- Role-based access control (`ADMIN`, `MANAGER`, `USER`) enforced with `@PreAuthorize`
- User CRUD with validation, unique usernames and BCrypt-hashed passwords
- Passwords are write-only: they never appear in any response
- One consistent JSON error format for every failure, including 401 and 403
- Optional first-admin seeding for fresh deployments
- Dockerfile and Docker Compose setup with PostgreSQL
- Unit, web-layer and end-to-end tests that run against an in-memory H2 database

## Tech stack

| Area | Technology |
|---|---|
| Language | Java 17 or newer (the Docker image uses 21) |
| Framework | Spring Boot 4.1, Spring MVC, Spring Security 7, Spring Data JPA |
| Database | PostgreSQL (H2 in tests) |
| Tokens | JJWT (RS256, 2048-bit RSA key pair) |
| Build | Maven (wrapper included: `./mvnw`) |
| Tests | JUnit 5, Mockito, AssertJ, MockMvc |

## Signing keys (RS256)

Tokens are signed with an RSA private key that only this service holds. Other services verify them with the matching public key and cannot create tokens themselves. Create the pair once, outside the project folder:

```bash
mkdir -p ~/.taskflow/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ~/.taskflow/keys/private.pem
openssl rsa -pubout -in ~/.taskflow/keys/private.pem -out ~/.taskflow/keys/public.pem
chmod 600 ~/.taskflow/keys/private.pem
```

- `private.pem` is read only by this service. Keep it out of the repository (add `*.pem` to `.gitignore`) and out of the Docker image.
- `public.pem` is not secret. It is the only key file the task API needs.
- The private key must be **PKCS#8** (the first line is `-----BEGIN PRIVATE KEY-----`), which is what the command above produces. A key starting with `BEGIN RSA PRIVATE KEY` is rejected at startup. Convert it with `openssl pkcs8 -topk8 -nocrypt -in old.pem -out private.pem`.
- This service derives its own public key from the private key at startup, so it never needs `public.pem`.
- If a private key is ever committed or shared, generate a new pair. Deleting the file from the repository is not enough.

## Quick start (Docker)

You need Docker with the Compose plugin.

```bash
# 1. Create the signing keys once (see "Signing keys (RS256)" above)

# 2. Create your environment file and fill it in
cp .env.example .env
#    - set JWT_ISSUER_ENV and JWT_AUDIENCE_ENV (the task API must use the same values)
#    - set ADMIN_USERNAME_ENV / ADMIN_PASSWORD_ENV for the first admin
#    - optional: JWT_PRIVATE_KEY_FILE, if the key is not at ~/.taskflow/keys/private.pem

# 3. Build and start the service and its database
docker compose up --build -d

# 4. Watch the startup logs (look for "Seeded initial admin user")
docker compose logs -f user-service

# 5. Log in
curl -i -X POST http://localhost:8022/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin01","password":"<your ADMIN_PASSWORD_ENV>"}'
```

Once the admin exists, remove `ADMIN_USERNAME_ENV` and `ADMIN_PASSWORD_ENV` from `.env` and restart, so the password does not stay in a file.

Compose mounts the private key into the container as a secret at `/run/secrets/jwt_private_key`, taken from `~/.taskflow/keys/private.pem` on the host (override the host path with `JWT_PRIVATE_KEY_FILE` in `.env`). The key is never copied into the image. The mounted key keeps the owner and permissions of the host file, so the compose file runs the container as `LOCAL_UID:LOCAL_GID` (both default to 1000) to let a key with mode `600` be read. If your IDs differ (check with `id -u` and `id -g`), set them in `.env`, or the service fails at startup with `AccessDeniedException`. The alternative, for a dev-only key, is `chmod 644`.

To stop: `docker compose down`. The data lives in the `user_db_data` volume and survives this. `docker compose down -v` deletes it.

The Compose file defines a healthcheck only for the database, and `user-service` waits for it through `depends_on`. There is no application healthcheck. If you need one, add `spring-boot-starter-actuator` and permit `/actuator/health` in `SecurityConfig`.

## Running locally

Prerequisites: JDK 17+ and a PostgreSQL database.

```bash
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/taskflow_users
export SPRING_DATASOURCE_USERNAME=taskflow
export SPRING_DATASOURCE_PASSWORD=change-me
export SPRING_JPA_HIBERNATE_DDL_AUTO=update
export JWT_PRIVATE_KEY_PATH=$HOME/.taskflow/keys/private.pem
export JWT_EXPIRATION_MS=3600000

# "dev" loads sample users (see below)
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

In PowerShell, set variables with `$env:JWT_PRIVATE_KEY_PATH="..."`. In an IDE, put them in the run configuration's environment variables. Variables defined in `.env` or the Compose file are not visible to a plain `mvn` run, so export the key path yourself. The app has no default for it and refuses to start without a readable key.

### Sample users (dev profile only)

With `-Dspring-boot.run.profiles=dev`, `DataLoader` **deletes all users** and creates four sample ones, all with the password `abcd1234`:

| Username | Role |
|---|---|
| `alice01` | ADMIN |
| `bob001` | MANAGER |
| `charlie` | USER |
| `david01` | USER |

These credentials are public. Never activate the `dev` profile against a database that holds real data, and never in a deployed environment.

## Configuration

Every property can be set in `application.properties` or as an environment variable (Spring's relaxed binding: dots and dashes become underscores, upper-cased).

| Property | Environment variable | Description |
|---|---|---|
| `jwt.private-key-path` | `JWT_PRIVATE_KEY_PATH` | Path to the PKCS#8 PEM private key. **Required, no default.** The app refuses to start if the file is missing or invalid. In Compose this is `/run/secrets/jwt_private_key`. |
| `jwt.issuer` | `JWT_ISSUER` | Value written to the `iss` claim and required when validating (default `user-service`). Consumers must use the same value. |
| `jwt.audience` | `JWT_AUDIENCE` | Value written to the `aud` claim and required when validating (default `taskflow-api`). Consumers must use the same value. |
| `jwt.expiration-ms` | `JWT_EXPIRATION_MS` | Token lifetime in milliseconds (default 3600000, one hour; in Compose it comes from `JWT_EXPIRATION_MS_ENV` in `.env`) |
| `spring.datasource.url` | `SPRING_DATASOURCE_URL` | JDBC URL |
| `spring.datasource.username` | `SPRING_DATASOURCE_USERNAME` | Database user |
| `spring.datasource.password` | `SPRING_DATASOURCE_PASSWORD` | Database password |
| `spring.jpa.hibernate.ddl-auto` | `SPRING_JPA_HIBERNATE_DDL_AUTO` | Schema handling. `update` is fine for a first run; use migrations for real data. |
| `spring.profiles.active` | `SPRING_PROFILES_ACTIVE` | Use `dev` for sample data. If it is unset (the Compose file does not set it), no profile is active and sample data stays off. |
| `app.seed-admin.username` | `APP_SEED_ADMIN_USERNAME` | Username of the first admin (see below) |
| `app.seed-admin.password` | `APP_SEED_ADMIN_PASSWORD` | Password of the first admin |

Never commit a private key (`*.pem`), a database password or `.env`. Keep secrets in environment variables, mounted secret files or a secrets manager.

### Creating the first admin

Creating users needs an admin token, and logging in needs a user, so a fresh database needs a bootstrap. `AdminSeeder` runs on every startup and creates one `ADMIN` when **both** `app.seed-admin.*` values are set **and** the `users` table is empty. Otherwise it does nothing.

- The username must follow the normal rules (6 to 20 lowercase letters or digits). Uppercase is lowercased automatically.
- The password must be 8 to 72 characters. A bad value stops startup with a clear message.
- A leftover setting is ignored once users exist, so it cannot block later startups.

## API

All request and response bodies are JSON. Authenticated endpoints expect `Authorization: Bearer <token>`.

| Method | Path | Access | Description |
|---|---|---|---|
| POST | `/auth/login` | Public | Exchange credentials for a token |
| POST | `/auth/validate` | ADMIN | Inspect any token (valid, expired, forged...) |
| GET | `/api/users` | ADMIN, MANAGER | List users |
| GET | `/api/users/{id}` | ADMIN, MANAGER, or the user themselves | Get one user |
| POST | `/api/users` | ADMIN | Create a user (`201`) |
| PUT | `/api/users/{id}` | ADMIN | Replace a user's details, password and role (`200`) |
| DELETE | `/api/users/{id}` | ADMIN | Delete a user (`204`) |

### Log in

```http
POST /auth/login
Content-Type: application/json

{ "username": "admin01", "password": "admin-pass-1" }
```

```json
{
  "token": "eyJhbGciOiJSUzI1NiJ9...",
  "valid": true,
  "claims": {
    "username": "admin01",
    "roles": ["ROLE_ADMIN"],
    "expiration": 1760000000000
  }
}
```

`expiration` is in epoch milliseconds. The username is case-insensitive at login. A wrong password and an unknown user return the same `401`, so callers cannot tell which one it was.

### Create a user

```http
POST /api/users
Authorization: Bearer <admin token>
Content-Type: application/json

{ "username": "newuser1", "password": "new-pass-123", "name": "New User", "role": "USER" }
```

```json
{ "id": 4, "username": "newuser1", "name": "New User", "role": "USER" }
```

`id` is read-only and ignored if sent. `password` is accepted on input and never returned.

### Inspect a token (admin)

```http
POST /auth/validate
Authorization: Bearer <admin token>
Content-Type: application/json

{ "token": "<token to inspect>" }
```

Always `200`. A good token returns `valid: true` with its `claims`. A bad one returns `valid: false` and an `error` of `EXPIRED`, `BAD_SIGNATURE`, `MALFORMED` or `EMPTY`.

### Validation rules

| Field | Rule |
|---|---|
| `username` | Required, 6 to 20 characters, lowercase letters and digits only, unique |
| `password` | Required, 8 to 72 characters (stored as a BCrypt hash) |
| `name` | Required, 2 to 50 characters |
| `role` | Required, one of `ADMIN`, `MANAGER`, `USER` |

### Errors

Every error uses the same shape:

```json
{ "message": "Authentication failed", "timestamp": "2026-10-05T06:00:00Z" }
```

| Status | When |
|---|---|
| 400 | Validation failure (the message lists `field: reason`), malformed JSON, or a bad path value such as `/api/users/abc` |
| 401 | No token, an invalid or expired token (the message says why), or failed login. Includes `WWW-Authenticate: Bearer`. |
| 403 | Authenticated, but the role does not allow it |
| 404 | Unknown user or unknown path |
| 405 | Wrong HTTP method |
| 409 | Username already taken, or a conflict with existing data |
| 500 | Unexpected error. The message is always generic, and details go to the server log only. |

## How authentication works

1. `POST /auth/login` hands the credentials to Spring Security. `DatabaseUserDetailsService` loads the user and BCrypt checks the password.
2. On success, `JwtService` signs a token with the RSA private key (RS256). The token carries `iss`, `aud`, the username (`sub`), `roles`, `iat` and `exp`.
3. On every later request, `JwtAuthFilter` reads the `Bearer` token and `JwtService` verifies it with the public key (derived from the private key at startup). The algorithm must be RS256, the issuer and audience must match the configuration, and the token must not be expired (30 seconds of clock skew is allowed). The filter then puts the username and roles into the security context. A bad token leaves the request anonymous, and the authorization rules then decide.
4. `SecurityConfig` requires authentication for everything except `/auth/login`. `@PreAuthorize` on the controllers enforces the roles.
5. Unauthenticated requests go through `RestAuthenticationEntryPoint`, which hands the exception to `GlobalExceptionHandler`. That is why 401 responses share the same JSON format as every other error.

Rules worth knowing:

- Roles are stored with a `ROLE_` prefix in the token (`ROLE_ADMIN`). Only `ROLE_` entries are ever read from or written to a token.
- A user can read their own profile through the `userSecurity` bean referenced in the `@PreAuthorize` rule.
- Spring Security 7 adds a `FACTOR_PASSWORD` authority at login. It is deliberately left out of the token.
- A rejected token is reported as `EXPIRED`, `BAD_SIGNATURE`, `MALFORMED` or `EMPTY`. Every other validation failure (wrong issuer or audience, missing subject or expiry, an unsupported algorithm) falls under `MALFORMED`. All of them give a 401.

## Design decisions

| Decision | Why |
|---|---|
| **RS256 instead of HS256** | With a shared secret, every service that verifies tokens could also forge them. With a key pair, only this service can sign, so a leak from a consumer cannot mint tokens. |
| **Public key derived from the private key** | This service issues and validates tokens, so deriving the public key at startup guarantees the two always match, with one file and one setting. |
| **Key loaded once at startup, from a file path** | A missing or malformed key stops the app immediately with a clear message. The key is never in code, the repository or the image. |
| **No default for the key path** | A misconfigured deployment must fail loudly, never start with the wrong key. |
| **Issuer and audience on every token** | A token signed with the right key but meant for something else is rejected. |
| **Algorithm pinned to RS256** | HS256 tokens keyed with the public key (algorithm confusion) and unsigned `alg: none` tokens are rejected. Both are covered by tests. |
| **Only `ROLE_*` roles are read from a token** | Anything else in the `roles` claim is ignored, and a missing or malformed claim means no authorities, never an error. |
| **Short-lived, stateless tokens** | Nothing is stored server-side, so tokens cannot be revoked. Keep the lifetime short and handle disabled users on this service. |

For the token format, key handling details and a troubleshooting table, see [AUTHENTICATION.md](AUTHENTICATION.md).

## Project structure

```
src/main/java/sg/edu/ntu/taskflow_api/users
├── auth         AuthController (login, validate)
├── config       SecurityConfig, AppConfig, AdminSeeder, DataLoader (dev only)
├── controller   UserController
├── dto          ClaimsDto, ErrorResponseDto, LoginRequestDto, JwtValidationRequestDto, TokenResponseDto
├── entity       User, UserRole
├── exception    GlobalExceptionHandler, InvalidTokenException, UserNotFoundException,
│                UsernameAlreadyExistsException
├── repository   UserRepository
├── security     JwtService, PemKeyLoader, JwtAuthFilter, RestAuthenticationEntryPoint, UserSecurity
└── service      UserService, UserServiceImpl, DatabaseUserDetailsService
```

## Testing

```bash
./mvnw test                                  # everything
./mvnw test -Dtest=UserControllerTest        # one class
```

Tests use an in-memory H2 database and their own settings in `src/test/resources/application.properties`, which **replaces** the main `application.properties` while tests run. A new main property needs adding there too if a test depends on it.

| Layer | Test classes |
|---|---|
| Repository | `UserRepositoryTest` |
| Services | `UserServiceImplTest`, `DatabaseUserDetailsServiceTest`, `UserSecurityTest`, `AdminSeederTest` |
| JWT and security | `JwtServiceTest`, `PemKeyLoaderTest`, `JwtAuthFilterTest`, `RestAuthenticationEntryPointTest` |
| Error handling | `GlobalExceptionHandlerTest` |
| Web layer (real security, mocked services) | `UserControllerTest`, `AuthControllerTest` |
| End to end (nothing mocked) | `UsersEndToEndTest` |

The end-to-end test starts the whole application and checks login, tokens, roles and the admin workflows against H2.

Tests never use your real keys. `TestJwtKeys` generates a throwaway RSA pair for each run, writes the private key to a temporary file and registers `jwt.private-key-path`, `jwt.issuer`, `jwt.audience` and `jwt.expiration-ms` through `@DynamicPropertySource`. Any test class that starts the Spring context needs the same `@DynamicPropertySource` (or a mocked `JwtService`), and the test `application.properties` must not define `jwt.secret` any more.

### Smoke test

`smoke-test.sh` checks the real running stack. Run it from the project root, on the host:

```bash
./smoke-test.sh --up --restart    # fresh stack, then also check tokens survive a restart
```

It logs in, checks the token (RS256, issuer, audience, roles, expiry), verifies the signature with `openssl` against `public.pem`, and confirms valid, tampered, garbage, unsigned and HS256 tokens, role rules and the 401 and 403 responses. It exits non-zero if any check fails. Run it after any change to security config, keys or Docker setup.

## Deployment checklist

- Provide the private key as a mounted secret or from a secrets manager, never in the image or the repository, and keep it readable only by the service. Set a strong database password through the environment.
- Use the same `JWT_ISSUER` and `JWT_AUDIENCE` here and in every consuming service.
- Do not run the `dev` profile. The Compose file does not activate it, and it must stay that way.
- Put a reverse proxy with TLS (Caddy, nginx or Traefik) in front, and do not expose port 8022 or the database port directly.
- Replace `ddl-auto=update` with Flyway or Liquibase migrations once the data matters, and check that the unique constraint on `username` exists.
- Back up the `user_db_data` volume.
- Keep `JWT_EXPIRATION_MS` short. Roles are baked into the token, so a role change or a deleted user only takes full effect when the old token expires.

## Using the tokens from another service

A service that needs to trust these tokens needs only `public.pem`. There is no secret to share, and it cannot create tokens. On every token it must check:

| Check | Value |
|---|---|
| Signature | RS256 only, verified with `public.pem`. Reject any other algorithm, including `none` and HS256. |
| `iss` | Equal to this service's `jwt.issuer` |
| `aud` | Contains this service's `jwt.audience` (it may be serialised as an array) |
| `exp` | Not in the past. A small clock skew is reasonable (30 seconds here). |

Then read `sub` (the username, lowercase) and `roles` (a list of names with the `ROLE_` prefix). The consumer must be configured with exactly the same issuer and audience, or every token is rejected with a 401 that looks like a signature problem.

## Known limitations

- No refresh tokens, logout or token revocation. A token is valid until it expires.
- No way for a user to change their own password yet. Only admins can update users.
- No rate limiting on `/auth/login`.
- Roles in a token can be stale until it expires.
- A single static key pair: there is no key rotation (that would need a `kid` header and a JWKS endpoint), and replacing the key invalidates every issued token.
- The private key is read from a file at startup. A secrets manager integration is not built in.

## Authentication reference

Click [here](README-authentication.md) for the token format, key handling and a troubleshooting table.

## Dockerfile

Click [here](README-Dockerfile.md) for run down on the `Dockerfile`.

## Docker Compose

Click [here](README-docker-compose.md) for walkthrough on the `docker-compose.yml`.
