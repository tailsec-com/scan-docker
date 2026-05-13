# @tailsec/scan-docker

Security scanner for Dockerfiles. Detects privileged containers, root users, hardcoded secrets, insecure base images, exposed ports, and other Docker misconfigurations.

[![npm](https://img.shields.io/npm/v/@tailsec/scan-docker)](https://www.npmjs.com/package/@tailsec/scan-docker)
[![CI](https://github.com/tailsec-com/scan-docker/actions/workflows/ci.yml/badge.svg)](https://github.com/tailsec-com/scan-docker)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Features

- Scans Dockerfile instructions for security issues
- Pattern-based detection using regex rules
- Supports multi-stage builds
- JSON output for CI/CD integration
- No external dependencies

## Installation

```bash
npm install -g @tailsec/scan-docker
```

## Usage

```bash
# Scan all Dockerfiles in a project
npx @tailsec/scan-docker "**/Dockerfile*"

# Scan a specific Dockerfile
npx @tailsec/scan-docker ./Dockerfile

# Output as JSON
npx @tailsec/scan-docker ./Dockerfile --json
```

### Programmatic

```typescript
import { scanDockerfile, formatDockerfileOutput } from '@tailsec/scan-docker';

const findings = scanDockerfile(dockerfileContent);
console.log(formatDockerfileOutput(findings));
```

## Supported File Types

| File Type | Extension |
|-----------|-----------|
| Dockerfile | `Dockerfile`, `Dockerfile.*` |
| Buildkit | `Dockerfile.buildkit` |

## Detection Rules

| Rule ID | Severity | Title |
|---------|----------|-------|
| docker-privileged | Critical | Container runs in privileged mode |
| docker-cap-add-all | Critical | Container adds all capabilities (--cap-add=ALL) |
| docker-secrets-env | Critical | Secret passed as environment variable |
| docker-hardcoded-secrets | Critical | Hardcoded secrets in Dockerfile |
| docker-user-root | High | Container runs as root user by default |
| docker-expose-port-22 | High | SSH port 22 exposed |
| docker-run-update | Medium | apt-get update without cleanup |
| docker-sudo | Medium | sudo command used |
| docker-copy-from-root | Medium | COPY from or between stages building as root |
| docker-wget-sh | Medium | wget/curl with --no-check-certificate |
| docker-apt-no-cache | Low | apt-get without --no-install-recommends |
| docker-latest-tag | Low | Base image uses :latest tag |
| docker-unqualified-image | Low | Base image not fully qualified |
| docker-add-insteaof-copy | Low | Use COPY instead of ADD when possible |
| docker-no-healthcheck | Low | No HEALTHCHECK instruction |

## Exit Codes

- `0` — Scan completed, no issues found
- `1` — Scan completed, issues found
- `2` — Scan failed (file errors, parse errors)

## Contributing

Rules are defined in `src/docker.ts` in the `DOCKER_RULES` array. Each rule has:

- `id` — Rule identifier (e.g., `docker-privileged`)
- `severity` — One of: `critical`, `high`, `medium`, `low`
- `title` — Human-readable description
- `pattern` — RegExp to match against each Dockerfile line

To add a new rule, append to the `DOCKER_RULES` array:

```typescript
{
  id: 'docker-my-new-rule',
  severity: 'high',
  title: 'Description of the issue',
  pattern: /pattern-to-match/,
}
```

Also update the `getAdvice()` function with remediation steps for the new rule.

## License

MIT