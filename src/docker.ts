export interface DockerFinding {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  instruction: string;
  line: number;
  advice: string[];
}

const DOCKER_RULES = [
  { id: 'docker-apt-no-cache', severity: 'low', title: 'apt-get without --no-install-recommends or cleanup',
    pattern: /apt-get\s+install(?!.*--no-install-recommends)/ },
  { id: 'docker-run-update', severity: 'medium', title: 'RUN apt-get update without cleanup',
    pattern: /apt-get\s+update(?![\s\S]*?rm\s+-rf\s+\/var\/lib\/apt)/ },
  { id: 'docker-latest-tag', severity: 'low', title: 'Base image uses :latest tag',
    pattern: /FROM\s+[\w\-\.]+:[Ll][Aa][Tt][Ee][Ss][Tt]/ },
  { id: 'docker-unqualified-image', severity: 'low', title: 'Base image not fully qualified',
    pattern: /FROM\s+(?!.*\/)[a-z][a-z0-9]*:[a-z0-9]/ },
  { id: 'docker-add-insteaof-copy', severity: 'low', title: 'Use COPY instead of ADD when possible',
    pattern: /ADD\s+(?!.*\.(?:tar|gzip|zip|tgz)\s)/ },
  { id: 'docker-privileged', severity: 'critical', title: 'Container runs in privileged mode',
    pattern: /--privileged/ },
  { id: 'docker-cap-add-all', severity: 'critical', title: 'Container adds all capabilities (--cap-add=ALL)',
    pattern: /--cap-add=ALL/ },
  { id: 'docker-user-root', severity: 'high', title: 'Container runs as root user by default',
    pattern: /USER\s+root/i },
  { id: 'docker-no-healthcheck', severity: 'low', title: 'No HEALTHCHECK instruction',
    pattern: /^(?!.*HEALTHCHECK)/ },
  { id: 'docker-expose-port-22', severity: 'high', title: 'SSH port 22 exposed',
    pattern: /EXPOSE\s+22\b/ },
  { id: 'docker-secrets-env', severity: 'critical', title: 'Secret passed as environment variable',
    pattern: /ENV\s+.*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)/i },
  { id: 'docker-hardcoded-secrets', severity: 'critical', title: 'Hardcoded secrets in Dockerfile',
    pattern: /ENV\s+[A-Z_]+=(?:(?![A-Z0-9]{16,}$).)*|RUN\s+.*(?:password|secret|token).*=/i },
  { id: 'docker-sudo', severity: 'medium', title: 'sudo command used',
    pattern: /sudo\s+/ },
  { id: 'docker-copy-from-root', severity: 'medium', title: 'COPY from or between stages building as root',
    pattern: /COPY\s+--from=(?:builder|build)/i },
  { id: 'docker-wget-sh', severity: 'medium', title: 'Use wget or curl with --no-check-certificate',
    pattern: /wget\s+.*--no-check-certificate|curl\s+.*--insecure/ },
];

export function scanDockerfile(content: string): DockerFinding[] {
  const lines = content.split('\n');
  const findings: DockerFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const rule of DOCKER_RULES) {
      if (rule.id === 'docker-no-healthcheck') {
        if (lineNum === 1 && !content.includes('HEALTHCHECK')) {
          findings.push({
            ruleId: rule.id,
            type: 'security',
            severity: rule.severity,
            title: rule.title,
            instruction: line.trim(),
            line: lineNum,
            advice: ['Add a HEALTHCHECK instruction to monitor container health'],
          });
        }
        continue;
      }

      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          type: 'security',
          severity: rule.severity,
          title: rule.title,
          instruction: line.trim(),
          line: lineNum,
          advice: getAdvice(rule.id),
        });
      }
    }
  }

  return findings;
}

function getAdvice(ruleId: string): string[] {
  const advice: Record<string, string[]> = {
    'docker-apt-no-cache': ['Use --no-install-recommends to reduce image size', 'Clean up apt cache after installation'],
    'docker-run-update': ['Remove apt cache with rm -rf /var/lib/apt/lists/* after apt-get update'],
    'docker-latest-tag': ['Use a specific tag like :latest-slim or pin to a version'],
    'docker-unqualified-image': ['Use a fully qualified image name with registry prefix'],
    'docker-add-insteaof-copy': ['Use COPY instead of ADD unless extracting archives'],
    'docker-privileged': ['Do not run containers in privileged mode'],
    'docker-cap-add-all': ['Use specific capability instead of ALL'],
    'docker-user-root': ['Create and use a non-root user with USER directive'],
    'docker-no-healthcheck': ['Add HEALTHCHECK instruction for container monitoring'],
    'docker-expose-port-22': ['Remove SSH exposure or ensure SSH is properly secured'],
    'docker-secrets-env': ['Use secrets management or runtime environment variables'],
    'docker-hardcoded-secrets': ['Use secret mounting or environment variable injection'],
    'docker-sudo': ['Avoid sudo; run commands as non-root user'],
    'docker-copy-from-root': ['Ensure COPY --from stages run as non-root user'],
    'docker-wget-sh': ['Validate SSL certificates instead of disabling verification'],
  };
  return advice[ruleId] || ['Review this Dockerfile instruction for security concerns'];
}

export function formatDockerfileOutput(findings: DockerFinding[]): string {
  if (findings.length === 0) return 'No security issues found.';
  const lines = [`Found ${findings.length} issue(s):`];
  for (const f of findings) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.title} (line ${f.line}): ${f.instruction}`);
  }
  return lines.join('\n');
}
