/**
 * ShieldPM — License Compliance Engine
 * Detects licenses from package metadata and enforces license policies.
 * Supports allow/deny lists, copyleft detection, and compliance reporting.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────

export type LicenseCategory = 'permissive' | 'copyleft' | 'weak-copyleft' | 'proprietary' | 'public-domain' | 'unknown';

export interface LicenseInfo {
  packageName: string;
  version: string;
  license: string;
  category: LicenseCategory;
  spdxId: string;
  source: 'package.json' | 'LICENSE' | 'inferred';
}

export interface LicensePolicy {
  allowed: string[];
  denied: string[];
  copyleftAllowed: boolean;
  requireLicense: boolean;
  exceptions: Record<string, string>; // packageName -> reason
}

export type LicenseViolationType = 'denied-license' | 'copyleft-in-proprietary' | 'no-license' | 'unknown-license';

export interface LicenseViolation {
  packageName: string;
  version: string;
  license: string;
  violationType: LicenseViolationType;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface LicenseReport {
  packages: LicenseInfo[];
  violations: LicenseViolation[];
  summary: {
    total: number;
    permissive: number;
    copyleft: number;
    weakCopyleft: number;
    publicDomain: number;
    proprietary: number;
    unknown: number;
    violations: number;
  };
  timestamp: string;
}

// ── License Classification ──────────────────────────────────────────────

const PERMISSIVE_LICENSES = new Set([
  'MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0',
  '0BSD', 'Unlicense', 'CC0-1.0', 'WTFPL', 'Zlib',
  'BSL-1.0', 'Artistic-2.0', 'Python-2.0', 'BlueOak-1.0.0',
]);

const COPYLEFT_LICENSES = new Set([
  'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'GPL-2.0', 'GPL-3.0', 'AGPL-3.0',
  'SSPL-1.0', 'OSL-3.0',
]);

const WEAK_COPYLEFT_LICENSES = new Set([
  'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'MPL-2.0', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0',
  'LGPL-2.1', 'LGPL-3.0',
  'CC-BY-SA-4.0',
]);

const PUBLIC_DOMAIN_LICENSES = new Set([
  'CC0-1.0', 'Unlicense', 'WTFPL', '0BSD',
]);

const LICENSE_ALIASES: Record<string, string> = {
  'mit': 'MIT',
  'isc': 'ISC',
  'bsd-2-clause': 'BSD-2-Clause',
  'bsd-3-clause': 'BSD-3-Clause',
  'apache-2.0': 'Apache-2.0',
  'apache 2.0': 'Apache-2.0',
  'apache2': 'Apache-2.0',
  'apache license 2.0': 'Apache-2.0',
  'gpl-2.0': 'GPL-2.0-only',
  'gplv2': 'GPL-2.0-only',
  'gpl-3.0': 'GPL-3.0-only',
  'gplv3': 'GPL-3.0-only',
  'lgpl-2.1': 'LGPL-2.1-only',
  'lgpl-3.0': 'LGPL-3.0-only',
  'mpl-2.0': 'MPL-2.0',
  'mpl 2.0': 'MPL-2.0',
  'unlicense': 'Unlicense',
  'cc0-1.0': 'CC0-1.0',
  'public domain': 'Unlicense',
  '0bsd': '0BSD',
  'artistic-2.0': 'Artistic-2.0',
  'bsl-1.0': 'BSL-1.0',
  'wtfpl': 'WTFPL',
  'agpl-3.0': 'AGPL-3.0-only',
};

function normalizeLicense(raw: string): string {
  const lower = raw.toLowerCase().trim();
  return LICENSE_ALIASES[lower] ?? raw;
}

export function classifyLicense(license: string): LicenseCategory {
  const normalized = normalizeLicense(license);

  if (PUBLIC_DOMAIN_LICENSES.has(normalized)) return 'public-domain';
  if (PERMISSIVE_LICENSES.has(normalized)) return 'permissive';
  if (COPYLEFT_LICENSES.has(normalized)) return 'copyleft';
  if (WEAK_COPYLEFT_LICENSES.has(normalized)) return 'weak-copyleft';

  // Handle SPDX expressions like "(MIT OR Apache-2.0)"
  if (normalized.includes(' OR ') || normalized.includes(' AND ')) {
    const parts = normalized.split(/\s+(?:OR|AND)\s+/).map((p) => p.replace(/[()]/g, '').trim());
    const categories = parts.map(classifyLicense);
    if (categories.every((c) => c === 'permissive' || c === 'public-domain')) return 'permissive';
    if (categories.some((c) => c === 'copyleft')) return 'copyleft';
    if (categories.some((c) => c === 'weak-copyleft')) return 'weak-copyleft';
  }

  return 'unknown';
}

// ── License Detection ───────────────────────────────────────────────────

async function detectLicenseFromFile(pkgDir: string): Promise<string | null> {
  const licenseFiles = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'COPYING'];

  for (const file of licenseFiles) {
    try {
      const content = await readFile(join(pkgDir, file), 'utf-8');
      const upper = content.toUpperCase();

      if (upper.includes('MIT LICENSE') || upper.includes('PERMISSION IS HEREBY GRANTED')) return 'MIT';
      if (upper.includes('ISC LICENSE')) return 'ISC';
      if (upper.includes('APACHE LICENSE') && upper.includes('VERSION 2.0')) return 'Apache-2.0';
      if (upper.includes('BSD 2-CLAUSE')) return 'BSD-2-Clause';
      if (upper.includes('BSD 3-CLAUSE')) return 'BSD-3-Clause';
      if (upper.includes('GNU GENERAL PUBLIC LICENSE') && upper.includes('VERSION 3')) return 'GPL-3.0-only';
      if (upper.includes('GNU GENERAL PUBLIC LICENSE') && upper.includes('VERSION 2')) return 'GPL-2.0-only';
      if (upper.includes('GNU LESSER GENERAL PUBLIC')) return 'LGPL-2.1-only';
      if (upper.includes('MOZILLA PUBLIC LICENSE') && upper.includes('2.0')) return 'MPL-2.0';
      if (upper.includes('UNLICENSE') || upper.includes('THIS IS FREE AND UNENCUMBERED')) return 'Unlicense';
    } catch { /* skip */ }
  }

  return null;
}

export async function detectLicense(packageName: string, projectDir: string): Promise<LicenseInfo> {
  const pkgDir = join(projectDir, 'node_modules', packageName);
  let license = '';
  let version = '0.0.0';
  let source: LicenseInfo['source'] = 'package.json';

  try {
    const pkgJson = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf-8'));
    version = pkgJson.version ?? '0.0.0';

    if (typeof pkgJson.license === 'string') {
      license = pkgJson.license;
      source = 'package.json';
    } else if (typeof pkgJson.license === 'object' && pkgJson.license?.type) {
      license = pkgJson.license.type;
      source = 'package.json';
    } else if (Array.isArray(pkgJson.licenses)) {
      license = pkgJson.licenses.map((l: { type?: string }) => l.type ?? '').filter(Boolean).join(' OR ');
      source = 'package.json';
    }
  } catch { /* ok */ }

  if (!license) {
    const fileLicense = await detectLicenseFromFile(pkgDir);
    if (fileLicense) {
      license = fileLicense;
      source = 'LICENSE';
    }
  }

  if (!license) {
    license = 'UNKNOWN';
    source = 'inferred';
  }

  const spdxId = normalizeLicense(license);
  const category = classifyLicense(spdxId);

  return { packageName, version, license: spdxId, category, spdxId, source };
}

// ── License Scanning ────────────────────────────────────────────────────

export async function scanLicenses(projectDir: string): Promise<LicenseInfo[]> {
  const results: LicenseInfo[] = [];

  let pkgJson: Record<string, unknown>;
  try {
    pkgJson = JSON.parse(await readFile(join(projectDir, 'package.json'), 'utf-8'));
  } catch {
    return results;
  }

  const deps = [
    ...Object.keys((pkgJson.dependencies as Record<string, string>) ?? {}),
    ...Object.keys((pkgJson.devDependencies as Record<string, string>) ?? {}),
  ];

  for (const dep of deps) {
    const info = await detectLicense(dep, projectDir);
    results.push(info);
  }

  return results.sort((a, b) => a.packageName.localeCompare(b.packageName));
}

// ── Policy enforcement ──────────────────────────────────────────────────

const DEFAULT_POLICY: LicensePolicy = {
  allowed: [],
  denied: ['AGPL-3.0-only', 'AGPL-3.0-or-later', 'SSPL-1.0'],
  copyleftAllowed: false,
  requireLicense: true,
  exceptions: {},
};

export function loadLicensePolicy(policyObj?: Partial<LicensePolicy>): LicensePolicy {
  return { ...DEFAULT_POLICY, ...policyObj };
}

export function checkCompliance(licenses: LicenseInfo[], policy: LicensePolicy): LicenseViolation[] {
  const violations: LicenseViolation[] = [];

  for (const pkg of licenses) {
    // Skip exceptions
    if (policy.exceptions[pkg.packageName]) continue;

    // Check denied licenses
    if (policy.denied.length > 0 && policy.denied.includes(pkg.spdxId)) {
      violations.push({
        packageName: pkg.packageName,
        version: pkg.version,
        license: pkg.spdxId,
        violationType: 'denied-license',
        message: `License "${pkg.spdxId}" is on the denied list`,
        severity: 'critical',
      });
      continue;
    }

    // Check allowed licenses (if allowlist is specified, only those are allowed)
    if (policy.allowed.length > 0 && !policy.allowed.includes(pkg.spdxId) && pkg.category !== 'unknown') {
      violations.push({
        packageName: pkg.packageName,
        version: pkg.version,
        license: pkg.spdxId,
        violationType: 'denied-license',
        message: `License "${pkg.spdxId}" is not on the allowed list`,
        severity: 'high',
      });
      continue;
    }

    // Check copyleft
    if (!policy.copyleftAllowed && pkg.category === 'copyleft') {
      violations.push({
        packageName: pkg.packageName,
        version: pkg.version,
        license: pkg.spdxId,
        violationType: 'copyleft-in-proprietary',
        message: `Copyleft license "${pkg.spdxId}" not allowed in proprietary projects`,
        severity: 'critical',
      });
      continue;
    }

    // Check missing license
    if (policy.requireLicense && (pkg.license === 'UNKNOWN' || pkg.category === 'unknown')) {
      violations.push({
        packageName: pkg.packageName,
        version: pkg.version,
        license: pkg.license,
        violationType: pkg.license === 'UNKNOWN' ? 'no-license' : 'unknown-license',
        message: pkg.license === 'UNKNOWN'
          ? 'Package has no declared license'
          : `License "${pkg.license}" is not a recognized SPDX identifier`,
        severity: 'medium',
      });
    }
  }

  return violations;
}

// ── Report generation ───────────────────────────────────────────────────

export function generateLicenseReport(licenses: LicenseInfo[], violations: LicenseViolation[]): LicenseReport {
  const summary = {
    total: licenses.length,
    permissive: licenses.filter((l) => l.category === 'permissive').length,
    copyleft: licenses.filter((l) => l.category === 'copyleft').length,
    weakCopyleft: licenses.filter((l) => l.category === 'weak-copyleft').length,
    publicDomain: licenses.filter((l) => l.category === 'public-domain').length,
    proprietary: licenses.filter((l) => l.category === 'proprietary').length,
    unknown: licenses.filter((l) => l.category === 'unknown').length,
    violations: violations.length,
  };

  return {
    packages: licenses,
    violations,
    summary,
    timestamp: new Date().toISOString(),
  };
}
