# Security checks

The users service runs its security checks in two CI jobs (`.github/workflows/ci.yml`): `dependency-check`
and `security`. They run in parallel with the tests, and **nothing is released, built, pushed or deployed
unless both pass**.

| Objective | Check | Where |
|---|---|---|
| Scan dependencies for known vulnerabilities | OWASP Dependency-Check 13.0.0, fails on CVSS 7.0 or higher. Data from the NVD API when the `NVD_API_KEY` secret is set, otherwise from Dependency-Check's daily NVD mirror | `dependency-check` job, plugin in `pom.xml` |
| Scan the Docker image (optional) | Trivy, fails on fixable HIGH or CRITICAL CVEs in the base image and the jars | `security` job, step *Vulnerability scan* |
| No secrets committed | gitleaks over the **whole git history** (passwords, tokens, API keys, private keys) | `security` job, step *Secret scan* |
| No secrets committed | `scripts/security-check.sh`: key files, private keys (PEM or base64), default passwords in properties and compose files, key handling in `.dockerignore` and `Dockerfile` | `security` job, step *Key and config hygiene* |
| No secrets in the image | The same script over the built image's files, plus its environment variables | `security` job, step *Check the image for keys* |
| Run the checks in CI | All of the above on every push to `main` | `ci.yml` |

## Running the checks locally

From the project root:

```bash
# Secrets and key handling (seconds)
./scripts/security-check.sh

# Secrets in the whole git history (install: https://github.com/gitleaks/gitleaks)
gitleaks git --redact --verbose .

# Dependencies, without an NVD API key: uses Dependency-Check's daily mirror of the NVD data
mvn dependency-check:check \
  -DnvdDatafeedUrl='https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/nvdcve-{0}.json.gz'
# or, with a key (free from https://nvd.nist.gov/developers/request-an-api-key), straight from the NVD API:
#   export NVD_API_KEY=...
#   mvn dependency-check:check
# The first run downloads the whole database and takes a while; later runs only fetch changes.
# report: target/dependency-check-report.html

# Container image (install: https://trivy.dev). --pull fetches the newest base image, as CI does.
docker build --pull -t taskflow-users:local .
trivy image --severity HIGH,CRITICAL --ignore-unfixed taskflow-users:local
```

## Where the secrets actually live

| Secret | Where it is kept |
|---|---|
| RS256 private key | `~/.taskflow/keys/private.pem` on the host, mounted read-only as a Docker secret. On Railway, the `JWT_PRIVATE_KEY_BASE64` variable. |
| Database password | `.env` (git-ignored), passed to compose. `.env.example` lists the names only. |
| Docker Hub token, SSH key, NVD API key (optional) | GitHub repository secrets |

`.gitignore` excludes `*.pem` and `.env`, and `.dockerignore` keeps both out of the image build.

## Findings from the first runs (27 October 2026)

| Check | Finding | Resolution |
|---|---|---|
| Dependency-Check | Tomcat 11.0.24 (from `spring-boot-starter-webmvc`): 11 CVEs, 9 of them HIGH or CRITICAL, including authentication and security-constraint bypasses. All fixed in Tomcat 11.0.25 | **Fixed:** Spring Boot upgraded from 4.1.1 to 4.1.2, which ships Tomcat 11.0.27 |
| Dependency-Check | `spring-boot-devtools`: CVE-2022-31691 (CRITICAL) | **False positive**, suppressed: the CVE is in the Spring Tools editor plugins for Eclipse and VS Code, matched by product name. Only those two product IDs are suppressed, so real Spring Boot CVEs are still reported |
| Dependency-Check | `opentelemetry-proto`: 5 MEDIUM CVEs (below the threshold) | **False positives**, suppressed: they are in the Go, .NET, C++ and JavaScript OpenTelemetry SDKs, not this Java jar |
| Trivy | `curl`, `libcurl` (CVE-2026-92392) and `brotli-libs` (CVE-2026-111497), all HIGH, in the Alpine runtime image | **Fixed:** `curl` was installed only for the health check, which now uses Alpine's built-in `wget`, so the packages are no longer in the image. `apk upgrade` applies Alpine fixes on every build, and CI builds with `pull: true` so a newer base image is never hidden by cached layers |
| gitleaks | 17 findings in old commits | **Reviewed, none live:** a retired HS256 secret (unused since the switch to RS256), expired example tokens in the README, code and docs that mention the PEM header, and a test-only key. Recorded in `.gitleaksignore`, one reason per group. A further 3 were search patterns in `security-check.sh`, allowlisted in `.gitleaks.toml` |
| `security-check.sh` | None | Passed on the first run |

After these changes, Dependency-Check reports no vulnerabilities above the threshold, and the Trivy scan of the image comes back clean.

## Handling findings

- **Dependency-Check or Trivy fails:** upgrade the library or base image. Upgrading the Spring Boot parent is usually the cleanest fix, because it updates Tomcat and the other managed libraries together. If a finding is a false positive, suppress it in `dependency-check-suppressions.xml` (or `.trivyignore`) with a reason and an expiry date.
- **gitleaks fails:** treat the secret as leaked even after deleting it, because it stays in the history. Revoke or rotate it first, then remove it. A reviewed finding in an old commit goes into `.gitleaksignore` (by fingerprint, with a comment). A pattern that is never a secret goes into `.gitleaks.toml` as a narrow allowlist entry.
- **`security-check.sh` fails:** it prints the file and line and what to change.