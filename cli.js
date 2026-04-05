#!/usr/bin/env node

import { setDefaultResultOrder } from 'node:dns';
import { createRequire } from 'node:module';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';

import { scanProject } from './src/core.js';

const require = createRequire(import.meta.url);
const { version: CLI_VERSION } = require('./package.json');

function brandingLine() {
  return `${chalk.bold('vuln-scan')}${chalk.gray(' - ')}${chalk.cyan('Debasis')}`;
}

function printHelp() {
  const valueLine = chalk.gray(`v${CLI_VERSION}`);
  const features = chalk.cyan('Fast | Secure | Protect');
  const tagline = chalk.gray('Scan Dependencies - Stay Safe - Fix Quickly');

  const text = `
${features}
${tagline}

${chalk.bold('vuln-scan')} ${valueLine}

Scans a project's lockfile (npm/pnpm/yarn) for known vulnerabilities using the OSV.dev API.

Made by Debasis (https://github.com/DebaA17)

Usage:
  npx vuln-scan
  pnpm dlx vuln-scan
  vuln-scan

Options:
  --json     Output machine-readable JSON
  --help     Show this help
`;
  console.log(text.trim());
}

function severityColor(sev) {
  switch (sev) {
    case 'CRITICAL':
      return chalk.redBright(sev);
    case 'HIGH':
      return chalk.red(sev);
    case 'MEDIUM':
      return chalk.yellow(sev);
    case 'LOW':
      return chalk.green(sev);
    default:
      return chalk.gray(sev || 'UNKNOWN');
  }
}

// Compare two semantic versions (returns true if v1 < v2)
function isVulnerable(installedVersion, fixedVersion) {
  const installedParts = installedVersion.split('.').map(Number);
  const fixedParts = fixedVersion.split('.').map(Number);

  for (let i = 0; i < Math.max(installedParts.length, fixedParts.length); i++) {
    const installed = installedParts[i] || 0;
    const fixed = fixedParts[i] || 0;
    if (installed < fixed) return true;
    if (installed > fixed) return false;
  }
  return false; // versions are equal → not vulnerable
}

async function main() {
  try {
    setDefaultResultOrder('ipv4first');
  } catch {
    // Older Node versions may not support this
  }

  const args = new Set(process.argv.slice(2));
  if (args.has('--help') || args.has('-h')) {
    printHelp();
    process.exit(0);
  }

  const jsonOutput = args.has('--json');

  const spinner = ora({ text: 'Scanning dependencies...', spinner: 'dots' }).start();

  try {
    const result = await scanProject({
      cwd: process.cwd(),
      onProgress: ({ processed, total }) => {
        spinner.text = `Scanning dependencies... ${processed}/${total}`;
      }
    });

    spinner.stop();

    // Filter vulnerabilities: only show if installed version < fixed version
    const activeVulns = result.vulnerabilities.filter(v => {
      if (!v.fixed) return true; // no fixed info, assume still vulnerable
      return isVulnerable(v.version, v.fixed);
    });

    if (jsonOutput) {
      console.log(JSON.stringify({ ...result, vulnerabilities: activeVulns }, null, 2));
      console.error(brandingLine());
      console.error(chalk.green('Scan complete!'));
      return;
    }

    if (activeVulns.length === 0) {
      console.log(chalk.green(`No known vulnerabilities found in ${result.dependencyCount} dependencies.`));
      console.log(brandingLine());
      console.log(chalk.green('Scan complete!'));
      return;
    }

    const table = new Table({
      head: ['Package', 'CVE ID', 'Severity', 'Summary'],
      wordWrap: true,
      colWidths: [28, 18, 10, 70]
    });

    for (const v of activeVulns) {
      const pkg = `${v.package}@${v.version}`;
      const cve = v.cve || v.id;
      const summary = v.summary + (v.fixed ? ` (Fix: ${v.fixed})` : '');
      table.push([pkg, cve, severityColor(v.severity), summary]);
    }

    console.log(table.toString());
    console.log(brandingLine());
    console.log(chalk.green('Scan complete!'));
  } catch (err) {
    spinner.stop();
    const message = err instanceof Error ? err.message : String(err);
    console.error(chalk.red(`Error: ${message}`));
    process.exitCode = 1;
  }
}

await main();