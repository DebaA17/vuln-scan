#!/usr/bin/env node

import { setDefaultResultOrder } from 'node:dns';

import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';

import { scanProject } from './src/core.js';

function printHelp() {
  const text = `
${chalk.bold('vuln-scan')}

Scans a project's lockfile (npm/pnpm/yarn) for known vulnerabilities using the OSV.dev API.

Usage:
  npx vuln-scan
  vuln-scan

Options:
  --json     Output machine-readable JSON
  --help     Show this help
`;
  // eslint-disable-next-line no-console
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

async function main() {
  // Some environments have broken/blocked IPv6 routes. Node's fetch (undici) may try IPv6 first
  // and time out even when IPv4 works (e.g., curl succeeds). Prefer IPv4 DNS results first.
  try {
    setDefaultResultOrder('ipv4first');
  } catch {
    // Older Node versions may not support this; best-effort.
  }

  const args = new Set(process.argv.slice(2));
  if (args.has('--help') || args.has('-h')) {
    printHelp();
    process.exit(0);
  }

  const jsonOutput = args.has('--json');

  const spinner = ora({ text: 'Scanning dependencies…', spinner: 'dots' }).start();

  try {
    const result = await scanProject({
      cwd: process.cwd(),
      onProgress: ({ processed, total }) => {
        spinner.text = `Scanning dependencies… ${processed}/${total}`;
      }
    });

    spinner.stop();

    if (jsonOutput) {
      // Keep stdout clean for piping/automation.
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(result, null, 2));
      // eslint-disable-next-line no-console
      console.error(chalk.green('Scan complete!'));
      return;
    }

    if (result.vulnerabilities.length === 0) {
      // eslint-disable-next-line no-console
      console.log(chalk.green(`No known vulnerabilities found in ${result.dependencyCount} dependencies.`));
      // eslint-disable-next-line no-console
      console.log(chalk.green('Scan complete!'));
      return;
    }

    const table = new Table({
      head: ['Package', 'CVE ID', 'Severity', 'Summary'],
      wordWrap: true,
      colWidths: [
        28,
        18,
        10,
        70
      ]
    });

    for (const v of result.vulnerabilities) {
      const pkg = `${v.package}@${v.version}`;
      const cve = v.cve || v.id;
      const summary = v.summary + (v.fixed ? ` (Fix: ${v.fixed})` : '');

      table.push([pkg, cve, severityColor(v.severity), summary]);
    }

    // eslint-disable-next-line no-console
    console.log(table.toString());
    // eslint-disable-next-line no-console
    console.log(chalk.green('Scan complete!'));
  } catch (err) {
    spinner.stop();
    const message = err instanceof Error ? err.message : String(err);
    // eslint-disable-next-line no-console
    console.error(chalk.red(`Error: ${message}`));
    process.exitCode = 1;
  }
}

await main();
