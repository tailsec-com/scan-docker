# @tailsec/scan-docker

Security scanner for Dockerfiles.

## Installation

```bash
npm install @tailsec/scan-docker
```

## CLI Usage

```bash
tailsec-scan-docker "**/Dockerfile*"
```

## API Usage

```typescript
import { scanDockerfile, formatDockerfileOutput } from '@tailsec/scan-docker';

const findings = scanDockerfile(dockerfileContent);
console.log(formatDockerfileOutput(findings));
```

## Rules

| Rule | Severity | Description |
|------|----------|-------------|
| docker-apt-no-cache | low | apt-get without --no-install-recommends |
| docker-run-update | medium | apt-get update without cleanup |
| docker-latest-tag | low | Base image uses :latest tag |
| docker-unqualified-image | low | Base image not fully qualified |
| docker-add-insteaof-copy | low | Use COPY instead of ADD |
| docker-privileged | critical | Container runs in privileged mode |
| docker-cap-add-all | critical | Container adds all capabilities |
| docker-user-root | high | Container runs as root user |
| docker-no-healthcheck | low | No HEALTHCHECK instruction |
| docker-expose-port-22 | high | SSH port 22 exposed |
| docker-secrets-env | critical | Secret passed as environment variable |
| docker-hardcoded-secrets | critical | Hardcoded secrets in Dockerfile |
| docker-sudo | medium | sudo command used |
| docker-copy-from-root | medium | COPY from stages building as root |
| docker-wget-sh | medium | wget/curl with --no-check-certificate |
