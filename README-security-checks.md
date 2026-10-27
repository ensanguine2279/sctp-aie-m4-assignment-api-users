# Security checks

The users service runs four security checks in its CI pipeline (`.github/workflows/ci.yml`).
They run in parallel with the tests, and **nothing is released, built, pushed or deployed unless all of them pass**.

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

# Container image (install: https://trivy.dev)
docker build -t taskflow-users:local .
trivy image --severity HIGH,CRITICAL --ignore-unfixed taskflow-users:local
```

## Where the secrets actually live

| Secret | Where it is kept |
|---|---|
| RS256 private key | `~/.taskflow/keys/private.pem` on the host, mounted read-only as a Docker secret. On Railway, the `JWT_PRIVATE_KEY_BASE64` variable. |
| Database password | `.env` (git-ignored), passed to compose. `.env.example` lists the names only. |
| Docker Hub token, SSH key, NVD API key (optional) | GitHub repository secrets |

`.gitignore` excludes `*.pem` and `.env`, and `.dockerignore` keeps both out of the image build.

## Handling findings

- **Dependency-Check or Trivy fails:** upgrade the library or base image. If a finding is a false positive, suppress it in `dependency-check-suppressions.xml` (or `.trivyignore`) with a reason and an expiry date.
- **gitleaks fails:** treat the secret as leaked even after deleting it, because it stays in the history. Revoke or rotate it first, then remove it. A false positive goes into `.gitleaks.toml` as a narrow allowlist entry.
- **`security-check.sh` fails:** it prints the file and line and what to change.
