import { scanDockerfile, formatDockerfileOutput } from './docker.js';
import { glob } from 'glob';
import * as fs from 'fs';

async function main() {
  const pattern = process.argv[2] || '**/Dockerfile*';

  const files = glob.sync(pattern, { nodir: true });
  if (files.length === 0) {
    console.log('No Dockerfile found matching:', pattern);
    process.exit(0);
  }

  for (const file of files) {
    console.log(`\nScanning: ${file}`);
    const content = fs.readFileSync(file, 'utf-8');
    const findings = scanDockerfile(content);
    console.log(formatDockerfileOutput(findings));
  }
}

main();
