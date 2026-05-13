import { scanDockerfile } from '../src/docker.js';

describe('Dockerfile security scanner', () => {
  describe('docker-apt-no-cache', () => {
    it('should detect apt-get install without --no-install-recommends', () => {
      const dockerfile = 'RUN apt-get install python3';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-apt-no-cache' }));
    });

    it('should not flag apt-get install with --no-install-recommends', () => {
      const dockerfile = 'RUN apt-get install --no-install-recommends python3';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-apt-no-cache');
    });
  });

  describe('docker-run-update', () => {
    it('should detect apt-get update without cleanup', () => {
      const dockerfile = 'RUN apt-get update && apt-get install python3';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-run-update' }));
    });

    it('should not flag apt-get update with cleanup', () => {
      const dockerfile = 'RUN apt-get update && rm -rf /var/lib/apt/lists/* && apt-get install python3';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-run-update');
    });
  });

  describe('docker-latest-tag', () => {
    it('should detect base image with :latest tag', () => {
      const dockerfile = 'FROM node:latest';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-latest-tag' }));
    });

    it('should not flag base image with specific tag', () => {
      const dockerfile = 'FROM node:18-alpine';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-latest-tag');
    });
  });

  describe('docker-unqualified-image', () => {
    it('should detect unqualified base image', () => {
      const dockerfile = 'FROM node:18-alpine';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-unqualified-image' }));
    });

    it('should not flag fully qualified images', () => {
      const dockerfile = 'FROM registry.example.com/node:18-alpine';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-unqualified-image');
    });
  });

  describe('docker-add-insteaof-copy', () => {
    it('should detect ADD without archive extension', () => {
      const dockerfile = 'ADD ./file.txt /app/';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-add-insteaof-copy' }));
    });

    it('should not flag ADD for tar archives', () => {
      const dockerfile = 'ADD ./file.tar /app/';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-add-insteaof-copy');
    });
  });

  describe('docker-privileged', () => {
    it('should detect --privileged flag', () => {
      const dockerfile = 'docker run --privileged myimage';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-privileged' }));
    });
  });

  describe('docker-cap-add-all', () => {
    it('should detect --cap-add=ALL', () => {
      const dockerfile = 'docker run --cap-add=ALL myimage';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-cap-add-all' }));
    });
  });

  describe('docker-user-root', () => {
    it('should detect USER root', () => {
      const dockerfile = 'USER root';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-user-root' }));
    });

    it('should detect USER ROOT', () => {
      const dockerfile = 'USER ROOT';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-user-root' }));
    });
  });

  describe('docker-expose-port-22', () => {
    it('should detect EXPOSE 22', () => {
      const dockerfile = 'EXPOSE 22';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-expose-port-22' }));
    });
  });

  describe('docker-secrets-env', () => {
    it('should detect ENV with SECRET', () => {
      const dockerfile = 'ENV MY_SECRET=abc123';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-secrets-env' }));
    });

    it('should detect ENV with PASSWORD', () => {
      const dockerfile = 'ENV DATABASE_PASSWORD=secret';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-secrets-env' }));
    });
  });

  describe('docker-sudo', () => {
    it('should detect sudo usage', () => {
      const dockerfile = 'RUN sudo apt-get update';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-sudo' }));
    });
  });

  describe('docker-copy-from-root', () => {
    it('should detect COPY --from=builder', () => {
      const dockerfile = 'COPY --from=builder /app/dist /app';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-copy-from-root' }));
    });
  });

  describe('docker-wget-sh', () => {
    it('should detect wget --no-check-certificate', () => {
      const dockerfile = 'RUN wget --no-check-certificate https://example.com/file';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-wget-sh' }));
    });

    it('should detect curl --insecure', () => {
      const dockerfile = 'RUN curl --insecure https://example.com/file';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-wget-sh' }));
    });
  });

  describe('docker-no-healthcheck', () => {
    it('should detect missing HEALTHCHECK on first line', () => {
      const dockerfile = 'FROM node:18\nRUN echo hello';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-no-healthcheck' }));
    });

    it('should not flag Dockerfile with HEALTHCHECK', () => {
      const dockerfile = 'FROM node:18\nHEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-no-healthcheck');
    });
  });

  describe('docker-copy-not-add', () => {
    it('should detect ADD with http URL', () => {
      const dockerfile = 'ADD https://example.com/file.tar /app/';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-copy-not-add' }));
    });

    it('should not flag COPY with http URL', () => {
      const dockerfile = 'COPY https://example.com/file.tar /app/';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-copy-not-add');
    });
  });

  describe('docker-user-not-root', () => {
    it('should detect non-root USER directive', () => {
      const dockerfile = 'FROM node:18\nUSER node';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-user-not-root' }));
    });

    it('should not flag USER root', () => {
      const dockerfile = 'USER root';
      const findings = scanDockerfile(dockerfile);
      const ids = findings.map(f => f.ruleId);
      expect(ids).not.toContain('docker-user-not-root');
    });
  });

  describe('docker-expose-weak', () => {
    it('should detect EXPOSE without comment', () => {
      const dockerfile = 'FROM node:18\nEXPOSE 3000';
      const findings = scanDockerfile(dockerfile);
      expect(findings).toContainEqual(expect.objectContaining({ ruleId: 'docker-expose-weak' }));
    });
  });
});
