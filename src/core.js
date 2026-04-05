import fs from 'node:fs/promises';
import path from 'node:path';

import yaml from 'js-yaml';
import yarnLockfile from '@yarnpkg/lockfile';

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

/**
 * Scan the current project by detecting its lockfile, extracting exact installed versions,
 * and querying OSV.dev for vulnerabilities.
 *
 * @param {object} params
 * @param {string} params.cwd - Working directory to scan.
 * @param {(progress: {processed: number, total: number}) => void} [params.onProgress]
 * @returns {Promise<{packageManager: string, dependencyCount: number, vulnerabilities: Array<object>}>}
 */
export async function scanProject({ cwd, onProgress }) {
  const projectPackageJsonPath = path.join(cwd, 'package.json');
  const hasPackageJson = await exists(projectPackageJsonPath);

  let detected;
  try {
    detected = await detectPackageManager(cwd);
  } catch {
    if (hasPackageJson) {
      throw new Error(
        'No supported lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock). ' +
          'Run your package manager install command to generate a lockfile, then re-run vuln-scan.'
      );
    }
    throw new Error(
      'Nothing to scan: no package.json or supported lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock). '
        + 'Run vuln-scan from a project directory.'
    );
  }

  const { packageManager, lockfilePath } = detected;

  const dependencies = await readDependenciesFromLockfile({
    packageManager,
    lockfilePath
  });

  const unique = uniqBy(dependencies, (d) => `${d.name}@${d.version}`);

  const vulns = await queryVulnerabilities({
    dependencies: unique,
    onProgress
  });

  // Flatten to one row per (package@version, vulnerability)
  const flattened = [];
  for (const item of vulns) {
    for (const vuln of item.vulns) {
      flattened.push({
        package: item.dependency.name,
        version: item.dependency.version,
        id: vuln.id,
        cve: vuln.cve,
        severity: vuln.severity,
        summary: vuln.summary,
        fixed: vuln.fixed
      });
    }
  }

  // Sort: most severe first, then package name
  flattened.sort((a, b) => {
    const s = severityRank(b.severity) - severityRank(a.severity);
    if (s !== 0) return s;
    const p = a.package.localeCompare(b.package);
    if (p !== 0) return p;
    return a.version.localeCompare(b.version);
  });

  return {
    packageManager,
    dependencyCount: unique.length,
    vulnerabilities: flattened
  };
}

async function detectPackageManager(cwd) {
  const candidates = [
    { packageManager: 'npm', file: 'package-lock.json' },
    { packageManager: 'pnpm', file: 'pnpm-lock.yaml' },
    { packageManager: 'yarn', file: 'yarn.lock' }
  ];

  for (const c of candidates) {
    const p = path.join(cwd, c.file);
    if (await exists(p)) {
      return { packageManager: c.packageManager, lockfilePath: p };
    }
  }

  throw new Error('No supported lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock).');
}

async function readDependenciesFromLockfile({ packageManager, lockfilePath }) {
  switch (packageManager) {
    case 'npm':
      return readFromNpmLockfile(lockfilePath);
    case 'pnpm':
      return readFromPnpmLockfile(lockfilePath);
    case 'yarn':
      return readFromYarnLockfile(lockfilePath);
    default:
      throw new Error(`Unsupported package manager: ${packageManager}`);
  }
}

/**
 * Parse npm's package-lock.json (v1/v2/v3).
 *
 * We prefer the "packages" section (npm v7+), because it includes exact installed versions.
 */
async function readFromNpmLockfile(lockfilePath) {
  const raw = await fs.readFile(lockfilePath, 'utf8');
  const data = JSON.parse(raw);

  const deps = [];

  if (data && data.packages && typeof data.packages === 'object') {
    for (const [key, value] of Object.entries(data.packages)) {
      if (!key || key === '') continue; // root
      if (!key.includes('node_modules/')) continue;
      if (!value || typeof value !== 'object') continue;
      if (!value.version) continue;

      const name = packageNameFromNpmPackagesKey(key);
      if (!name) continue;

      deps.push({ name, version: String(value.version) });
    }

    return deps;
  }

  // Fallback for older lockfiles: top-level "dependencies".
  if (data && data.dependencies && typeof data.dependencies === 'object') {
    collectNpmDepsRecursive(data.dependencies, deps);
    return deps;
  }

  throw new Error('Unsupported or invalid package-lock.json format.');
}

function packageNameFromNpmPackagesKey(key) {
  // Examples:
  // - node_modules/react
  // - node_modules/@types/node
  // - node_modules/a/node_modules/b
  const idx = key.lastIndexOf('node_modules/');
  if (idx === -1) return null;
  return key.slice(idx + 'node_modules/'.length);
}

function collectNpmDepsRecursive(node, out) {
  for (const [name, info] of Object.entries(node)) {
    if (!info || typeof info !== 'object') continue;
    if (info.version) out.push({ name, version: String(info.version) });
    if (info.dependencies && typeof info.dependencies === 'object') {
      collectNpmDepsRecursive(info.dependencies, out);
    }
  }
}

/**
 * Parse pnpm-lock.yaml.
 *
 * pnpm stores installed packages under the "packages" map with keys like:
 *   /react/18.2.0
 *   /@types/node/20.11.17
 */
async function readFromPnpmLockfile(lockfilePath) {
  const raw = await fs.readFile(lockfilePath, 'utf8');
  const data = yaml.load(raw);
  if (!data || typeof data !== 'object') {
    throw new Error('Invalid pnpm-lock.yaml');
  }

  const packages = /** @type {any} */ (data).packages;
  if (!packages || typeof packages !== 'object') {
    throw new Error('pnpm-lock.yaml does not contain a "packages" section.');
  }

  const deps = [];
  for (const key of Object.keys(packages)) {
    // Ignore non-package keys.
    if (typeof key !== 'string') continue;

    const parsed = parsePnpmPackageKey(key);
    if (!parsed) continue;

    deps.push(parsed);
  }

  return deps;
}

function parsePnpmPackageKey(key) {
  // pnpm lockfile keys vary across versions.
  // Examples:
  //  - /react/18.2.0
  //  - /@types/node/20.11.17
  //  - chalk@5.6.2
  //  - @yarnpkg/lockfile@1.1.0
  // Keys may include peers in parentheses, e.g. foo@1.0.0(bar@2.0.0)

  const noPeers = key.split('(')[0].trim();
  if (!noPeers) return null;

  if (noPeers.startsWith('/')) {
    const parts = noPeers.split('/').filter(Boolean);
    if (parts.length < 2) return null;

    const version = parts[parts.length - 1];
    const name = parts.slice(0, parts.length - 1).join('/');
    if (!name || !version) return null;

    return { name, version };
  }

  // name@version (scoped or unscoped). Split on last '@'.
  const at = noPeers.lastIndexOf('@');
  if (at <= 0) return null;

  const name = noPeers.slice(0, at);
  const version = noPeers.slice(at + 1);
  if (!name || !version) return null;

  return { name, version };
}

/**
 * Parse yarn.lock.
 *
 * Uses @yarnpkg/lockfile to support Yarn v1-style lockfiles.
 */
async function readFromYarnLockfile(lockfilePath) {
  const raw = await fs.readFile(lockfilePath, 'utf8');
  const parsed = yarnLockfile.parse(raw);

  if (!parsed || parsed.type !== 'success' || !parsed.object) {
    throw new Error('Failed to parse yarn.lock');
  }

  const deps = [];

  // `parsed.object` keys look like: "react@^18.2.0, react@~18.2.0".
  // The value contains the resolved version.
  for (const [selector, value] of Object.entries(parsed.object)) {
    if (!value || typeof value !== 'object') continue;
    const version = /** @type {any} */ (value).version;
    if (!version) continue;

    // Selectors can be multiple entries separated by ",".
    const first = selector.split(',')[0].trim();
    const name = yarnSelectorToName(first);
    if (!name) continue;

    deps.push({ name, version: String(version) });
  }

  return deps;
}

function yarnSelectorToName(selector) {
  // Examples:
  //  react@^18.2.0
  //  @types/node@^20.0.0
  //  "@scope/name@npm:^1.2.3" (rare) => we strip quotes and protocols

  const s = selector.replace(/^"|"$/g, '');

  // Strip possible protocol prefixes (yarn berry selectors):
  //   pkg@npm:1.2.3
  //   pkg@workspace:*
  const npmPrefix = '@npm:';
  const protocolIndex = s.indexOf(npmPrefix);
  if (protocolIndex !== -1) {
    // "name@npm:range" -> keep "name@range" for parsing
    const before = s.slice(0, protocolIndex);
    const after = s.slice(protocolIndex + npmPrefix.length);
    return yarnSelectorToName(`${before}@${after}`);
  }

  if (s.startsWith('@')) {
    // Scoped package: @scope/name@range => split on last '@'
    const idx = s.lastIndexOf('@');
    if (idx <= 0) return null;
    return s.slice(0, idx);
  }

  // Unscoped: name@range
  const idx = s.indexOf('@');
  if (idx === -1) return null;
  return s.slice(0, idx);
}

async function queryVulnerabilities({ dependencies, onProgress }) {
  const concurrency = 12;
  let processed = 0;
  const total = dependencies.length;

  const results = [];

  await promisePool({
    items: dependencies,
    concurrency,
    worker: async (dependency) => {
      const response = await queryOsv({ name: dependency.name, version: dependency.version });
      const normalized = normalizeOsvResponse({ dependency, response });
      results.push({ dependency, vulns: normalized });

      processed += 1;
      if (onProgress) onProgress({ processed, total });
    }
  });

  // Keep only dependencies with vulnerabilities
  return results.filter((r) => r.vulns.length > 0);
}

async function queryOsv({ name, version }) {
  const body = {
    version,
    package: {
      name,
      ecosystem: 'npm'
    }
  };

  const res = await fetchWithRetry(OSV_QUERY_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // A friendly UA can help with debugging/telemetry on the server side.
      'user-agent': 'vuln-scan (node)'
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const text = await safeReadText(res);
    throw new Error(`OSV query failed for ${name}@${version} (${res.status}): ${text}`);
  }

  return res.json();
}

async function fetchWithRetry(url, init) {
  const retries = 3;
  const timeoutMs = 15_000;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      // eslint-disable-next-line no-undef
      return await fetch(url, {
        ...init,
        signal: controller.signal
      });
    } catch (err) {
      const isLast = attempt === retries;
      const message = err instanceof Error ? err.message : String(err);
      const code = extractNodeErrorCode(err);

      if (isLast) {
        // Provide a more actionable message than the generic "fetch failed".
        if (code === 'ETIMEDOUT' || code === 'ENETUNREACH' || code === 'EAI_AGAIN') {
          throw new Error(
            `Network error reaching OSV.dev (${code}). ` +
              `If you're on an IPv6-restricted network, try: NODE_OPTIONS=--dns-result-order=ipv4first vuln-scan`
          );
        }
        throw new Error(`Failed to reach OSV.dev: ${message}`);
      }

      // Retry transient network issues / timeouts.
      if (code === 'ETIMEDOUT' || code === 'ECONNRESET' || code === 'ENETUNREACH' || code === 'EAI_AGAIN') {
        await delay(250 * Math.pow(2, attempt));
        continue;
      }

      // AbortError or other non-network errors should fail fast.
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  // Unreachable.
  throw new Error('Failed to reach OSV.dev.');
}

function extractNodeErrorCode(err) {
  // Node/undici errors often have nested causes.
  const code = err?.cause?.code || err?.code;
  return typeof code === 'string' ? code : null;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeOsvResponse({ dependency, response }) {
  const vulns = Array.isArray(response?.vulns) ? response.vulns : [];

  return vulns.map((v) => {
    const id = String(v.id || '');
    const cve = findCveAlias(v);
    const summary = String(v.summary || v.details || '');
    const severity = computeSeverity(v);
    const fixed = extractFixedVersion({ vuln: v, packageName: dependency.name });

    return {
      id,
      cve,
      summary: summary.trim().replace(/\s+/g, ' '),
      severity,
      fixed
    };
  });
}

function findCveAlias(vuln) {
  const aliases = Array.isArray(vuln?.aliases) ? vuln.aliases : [];
  const cve = aliases.find((a) => typeof a === 'string' && a.startsWith('CVE-'));
  return cve || null;
}

function computeSeverity(vuln) {
  // OSV uses `severity` entries like: { type: "CVSS_V3", score: "9.8" }
  const sev = Array.isArray(vuln?.severity) ? vuln.severity : [];

  const scores = sev
    .map((s) => {
      const score = typeof s?.score === 'string' ? parseFloat(s.score) : NaN;
      return Number.isFinite(score) ? score : null;
    })
    .filter((x) => x !== null);

  const maxScore = scores.length ? Math.max(...scores) : null;

  // Some records have a database-specific severity label.
  const dbSev = vuln?.database_specific?.severity;
  if (typeof dbSev === 'string') {
    const normalized = dbSev.toUpperCase();
    if (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(normalized)) return normalized;
  }

  if (maxScore === null) return 'UNKNOWN';
  if (maxScore >= 9) return 'CRITICAL';
  if (maxScore >= 7) return 'HIGH';
  if (maxScore >= 4) return 'MEDIUM';
  if (maxScore > 0) return 'LOW';
  return 'UNKNOWN';
}

function severityRank(sev) {
  switch (sev) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}

function extractFixedVersion({ vuln, packageName }) {
  // Try to find any `fixed` event in affected ranges for this package.
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];

  for (const a of affected) {
    const pName = a?.package?.name;
    if (pName && pName !== packageName) continue;

    const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r?.events) ? r.events : [];
      for (const e of events) {
        if (typeof e?.fixed === 'string' && e.fixed.trim()) {
          return e.fixed.trim();
        }
      }
    }
  }

  // Some ecosystems store it elsewhere.
  const dbFixed = vuln?.database_specific?.fixed;
  if (typeof dbFixed === 'string' && dbFixed.trim()) return dbFixed.trim();

  return null;
}

async function safeReadText(res) {
  try {
    return await res.text();
  } catch {
    return '';
  }
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function uniqBy(items, keyFn) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

async function promisePool({ items, concurrency, worker }) {
  const queue = items.slice();
  const workers = [];

  const runOne = async () => {
    while (queue.length) {
      const item = queue.shift();
      if (item === undefined) return;
      await worker(item);
    }
  };

  for (let i = 0; i < Math.max(1, concurrency); i += 1) {
    workers.push(runOne());
  }

  await Promise.all(workers);
}
