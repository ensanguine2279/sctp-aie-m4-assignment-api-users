# Module 4 Assignment - TaskFlow Users Service

A Spring Boot REST service that manages users and issues JWTs for the TaskFlow system. It handles registration by an admin, login, role-based access control and token inspection. The task APIs live in a separate project, which trusts the tokens this service issues.

## Features

- Stateless authentication with signed JWTs (HS256), with the user's roles inside the token
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
| Tokens | JJWT (HS256) |
| Build | Maven (wrapper included: `./mvnw`) |
| Tests | JUnit 5, Mockito, AssertJ, MockMvc |

## Quick start (Docker)

You need Docker with the Compose plugin.

```bash
# 1. Create your environment file and fill it in
cp .env.example .env
#    - generate a JWT secret:  openssl rand -base64 48
#    - set ADMIN_USERNAME / ADMIN_PASSWORD for the first admin

# 2. Build and start the service and its database
docker compose up --build -d

# 3. Watch the startup logs (look for "Seeded initial admin user")
docker compose logs -f users-service

# 4. Log in
curl -i -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin01","password":"<your ADMIN_PASSWORD>"}'
```

Once the admin exists, remove `ADMIN_USERNAME` and `ADMIN_PASSWORD` from `.env` and restart, so the password does not stay in a file.

To stop: `docker compose down`. The data lives in the `pgdata` volume and survives this. `docker compose down -v` deletes it.

The compose healthcheck calls `/actuator/health`, which needs `spring-boot-starter-actuator` and that path permitted in `SecurityConfig`. If you don't use actuator, delete the `healthcheck:` block.

## Running locally

Prerequisites: JDK 17+ and a PostgreSQL database.

```bash
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/taskflow_users
export SPRING_DATASOURCE_USERNAME=taskflow
export SPRING_DATASOURCE_PASSWORD=change-me
export SPRING_JPA_HIBERNATE_DDL_AUTO=update
export JWT_SECRET=$(openssl rand -base64 48)
export JWT_EXPIRATION_MS=3600000

# "dev" loads sample users (see below)
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

In PowerShell, set variables with `$env:JWT_SECRET="..."`. In an IDE, put them in the run configuration's environment variables.

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
| `jwt.secret` | `JWT_SECRET` | HS256 signing secret, **at least 32 bytes**. The app refuses to start with a shorter one. |
| `jwt.expiration-ms` | `JWT_EXPIRATION_MS` | Token lifetime in milliseconds (the Compose default is 900000, 15 minutes) |
| `spring.datasource.url` | `SPRING_DATASOURCE_URL` | JDBC URL |
| `spring.datasource.username` | `SPRING_DATASOURCE_USERNAME` | Database user |
| `spring.datasource.password` | `SPRING_DATASOURCE_PASSWORD` | Database password |
| `spring.jpa.hibernate.ddl-auto` | `SPRING_JPA_HIBERNATE_DDL_AUTO` | Schema handling. `update` is fine for a first run; use migrations for real data. |
| `spring.profiles.active` | `SPRING_PROFILES_ACTIVE` | Use `dev` for sample data. Anything else (Compose sets `prod`) keeps it off. |
| `app.seed-admin.username` | `APP_SEED_ADMIN_USERNAME` | Username of the first admin (see below) |
| `app.seed-admin.password` | `APP_SEED_ADMIN_PASSWORD` | Password of the first admin |

Never commit a real `jwt.secret` or database password. Keep secrets in environment variables or a secrets manager, and leave `.env` out of version control.

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
  "token": "eyJhbGciOiJIUzI1NiJ9...",
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
2. On success, `JwtService` signs a token with the username (`sub`), `roles`, `iat` and `exp`.
3. On every later request, `JwtAuthFilter` reads the `Bearer` token, verifies it, and puts the username and roles into the security context. A bad token leaves the request anonymous, and the authorization rules then decide.
4. `SecurityConfig` requires authentication for everything except `/auth/login`. `@PreAuthorize` on the controllers enforces the roles.
5. Unauthenticated requests go through `RestAuthenticationEntryPoint`, which hands the exception to `GlobalExceptionHandler`. That is why 401 responses share the same JSON format as every other error.

Rules worth knowing:

- Roles are stored with a `ROLE_` prefix in the token (`ROLE_ADMIN`). Only `ROLE_` entries are ever read from or written to a token.
- A user can read their own profile through the `userSecurity` bean referenced in the `@PreAuthorize` rule.

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
├── security     JwtService, JwtAuthFilter, RestAuthenticationEntryPoint, UserSecurity
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
| JWT and security | `JwtServiceTest`, `JwtAuthFilterTest`, `RestAuthenticationEntryPointTest` |
| Error handling | `GlobalExceptionHandlerTest` |
| Web layer (real security, mocked services) | `UserControllerTest`, `AuthControllerTest` |
| End to end (nothing mocked) | `UsersEndToEndTest` |

The end-to-end test starts the whole application and checks login, tokens, roles and the admin workflows against H2.

## Deployment checklist

- Set a strong `JWT_SECRET` (at least 32 random bytes) and database password through the environment.
- Do not run the `dev` profile. Compose sets `SPRING_PROFILES_ACTIVE=prod`.
- Put a reverse proxy with TLS (Caddy, nginx or Traefik) in front, and do not expose port 8080 or the database port directly.
- Replace `ddl-auto=update` with Flyway or Liquibase migrations once the data matters, and check that the unique constraint on `username` exists.
- Back up the `pgdata` volume.
- Keep `JWT_EXPIRATION_MS` short. Roles are baked into the token, so a role change or a deleted user only takes full effect when the old token expires.

## Using the tokens from another service

A service that needs to trust these tokens verifies the signature and reads three claims:

| Claim | Meaning |
|---|---|
| `sub` | The username (lowercase) |
| `roles` | List of role names with the `ROLE_` prefix |
| `exp` | Expiry (standard JWT seconds) |

Today that means sharing `JWT_SECRET`, which also lets the other service mint tokens. Moving to asymmetric keys (RS256 or ES256) would let it verify tokens without being able to create them.

## Known limitations

- No refresh tokens, logout or token revocation. A token is valid until it expires.
- No way for a user to change their own password yet. Only admins can update users.
- No rate limiting on `/auth/login`.
- Roles in a token can be stale until it expires.
- A single shared HS256 secret across services.

## Dockerfile

Click [here](README-Dockerfile.md) for run down on the `Dockerfile`.

## Docker Compose

Click [here](README-docker-compose.md) for walkthrough on the `docker-compose.yml`.
