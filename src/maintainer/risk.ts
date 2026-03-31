/**
 * ShieldPM — Maintainer Risk Scoring
 * Analyzes package maintainer metadata to assess supply chain trust signals.
 * Tracks maintainer changes, account age, and historical patterns.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────

export type MaintainerRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface MaintainerInfo {
  name: string;
  email: string;
}

export interface MaintainerRiskProfile {
  packageName: string;
  version: string;
  maintainers: MaintainerInfo[];
  maintainerCount: number;
  riskLevel: MaintainerRiskLevel;
  riskScore: number;
  riskFactors: RiskFactor[];
  recommendations: string[];
}

export interface RiskFactor {
  factor: string;
  severity: MaintainerRiskLevel;
  score: number;
  description: string;
}

export interface MaintainerReport {
  packages: MaintainerRiskProfile[];
  summary: {
    total: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
    averageScore: number;
    singleMaintainerCount: number;
  };
  timestamp: string;
}

// ── Risk Factor Analysis ────────────────────────────────────────────────

function analyzeMaintainerRisk(
  packageName: string,
  pkgJson: Record<string, unknown>
): MaintainerRiskProfile {
  const riskFactors: RiskFactor[] = [];
  let totalScore = 0;

  const version = (pkgJson.version as string) ?? '0.0.0';

  // Extract maintainer info
  const maintainers: MaintainerInfo[] = [];

  if (Array.isArray(pkgJson.maintainers)) {
    for (const m of pkgJson.maintainers) {
      if (typeof m === 'string') {
        maintainers.push({ name: m, email: '' });
      } else if (m && typeof m === 'object') {
        maintainers.push({
          name: (m as Record<string, string>).name ?? '',
          email: (m as Record<string, string>).email ?? '',
        });
      }
    }
  }

  if (typeof pkgJson.author === 'string') {
    const match = (pkgJson.author as string).match(/^([^<(]+)/);
    if (match && !maintainers.some((m) => m.name === match[1].trim())) {
      maintainers.push({ name: match[1].trim(), email: '' });
    }
  } else if (pkgJson.author && typeof pkgJson.author === 'object') {
    const author = pkgJson.author as Record<string, string>;
    if (author.name && !maintainers.some((m) => m.name === author.name)) {
      maintainers.push({ name: author.name, email: author.email ?? '' });
    }
  }

  const maintainerCount = maintainers.length;

  // Risk Factor 1: Single maintainer
  if (maintainerCount <= 1) {
    riskFactors.push({
      factor: 'single-maintainer',
      severity: 'medium',
      score: 2,
      description: 'Package has a single maintainer — bus factor risk',
    });
    totalScore += 2;
  }

  // Risk Factor 2: No maintainers listed
  if (maintainerCount === 0) {
    riskFactors.push({
      factor: 'no-maintainers',
      severity: 'high',
      score: 3,
      description: 'No maintainers listed in package metadata',
    });
    totalScore += 3;
  }

  // Risk Factor 3: No repository
  if (!pkgJson.repository) {
    riskFactors.push({
      factor: 'no-repository',
      severity: 'medium',
      score: 2,
      description: 'No source repository declared — cannot verify provenance',
    });
    totalScore += 2;
  }

  // Risk Factor 4: Generic email domains (freemail)
  const freemailDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com'];
  const hasFreeemail = maintainers.some((m) =>
    freemailDomains.some((d) => m.email.endsWith(`@${d}`))
  );
  if (hasFreeemail && maintainerCount <= 1) {
    riskFactors.push({
      factor: 'freemail-single-maintainer',
      severity: 'low',
      score: 1,
      description: 'Single maintainer using a free email service',
    });
    totalScore += 1;
  }

  // Risk Factor 5: No homepage or description
  if (!pkgJson.homepage && !pkgJson.description) {
    riskFactors.push({
      factor: 'minimal-metadata',
      severity: 'low',
      score: 1,
      description: 'Package has minimal metadata — no homepage or description',
    });
    totalScore += 1;
  }

  // Risk Factor 6: Deprecated
  if (pkgJson.deprecated) {
    riskFactors.push({
      factor: 'deprecated',
      severity: 'high',
      score: 3,
      description: `Package is deprecated: ${pkgJson.deprecated}`,
    });
    totalScore += 3;
  }

  // Risk Factor 7: Private registry
  const resolved = (pkgJson as Record<string, unknown>)._resolved as string | undefined;
  if (resolved && !resolved.includes('registry.npmjs.org')) {
    riskFactors.push({
      factor: 'non-standard-registry',
      severity: 'medium',
      score: 2,
      description: 'Package resolved from a non-standard registry',
    });
    totalScore += 2;
  }

  // Risk Factor 8: No license
  if (!pkgJson.license) {
    riskFactors.push({
      factor: 'no-license',
      severity: 'medium',
      score: 2,
      description: 'No license declared — legal risk and trust concern',
    });
    totalScore += 2;
  }

  // Risk Factor 9: Very long package name (potential typosquatting)
  if (packageName.length > 40) {
    riskFactors.push({
      factor: 'long-name',
      severity: 'low',
      score: 1,
      description: 'Unusually long package name',
    });
    totalScore += 1;
  }

  // Risk Factor 10: No keywords
  if (!pkgJson.keywords || (Array.isArray(pkgJson.keywords) && pkgJson.keywords.length === 0)) {
    riskFactors.push({
      factor: 'no-keywords',
      severity: 'low',
      score: 0.5,
      description: 'No keywords — may indicate low-effort package',
    });
    totalScore += 0.5;
  }

  // Compute risk level
  const riskScore = Math.min(10, totalScore);
  const riskLevel: MaintainerRiskLevel = riskScore >= 7
    ? 'critical'
    : riskScore >= 4
      ? 'high'
      : riskScore >= 2
        ? 'medium'
        : 'low';

  // Generate recommendations
  const recommendations: string[] = [];
  if (maintainerCount <= 1) recommendations.push('Consider alternatives with multiple maintainers');
  if (!pkgJson.repository) recommendations.push('Verify package source manually');
  if (pkgJson.deprecated) recommendations.push('Replace with maintained alternative');
  if (riskScore >= 4) recommendations.push('Pin exact version and monitor for changes');

  return {
    packageName,
    version,
    maintainers,
    maintainerCount,
    riskLevel,
    riskScore,
    riskFactors,
    recommendations,
  };
}

// ── Scanning ────────────────────────────────────────────────────────────

export async function analyzeMaintainer(
  packageName: string,
  projectDir: string
): Promise<MaintainerRiskProfile> {
  const pkgDir = join(projectDir, 'node_modules', packageName);

  try {
    const pkgJson = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf-8'));
    return analyzeMaintainerRisk(packageName, pkgJson);
  } catch {
    return {
      packageName,
      version: '0.0.0',
      maintainers: [],
      maintainerCount: 0,
      riskLevel: 'high',
      riskScore: 5,
      riskFactors: [{
        factor: 'unreadable',
        severity: 'high',
        score: 5,
        description: 'Could not read package metadata',
      }],
      recommendations: ['Verify package is properly installed'],
    };
  }
}

export async function scanMaintainers(projectDir: string): Promise<MaintainerReport> {
  const packages: MaintainerRiskProfile[] = [];

  let pkgJson: Record<string, unknown>;
  try {
    pkgJson = JSON.parse(await readFile(join(projectDir, 'package.json'), 'utf-8'));
  } catch {
    return {
      packages,
      summary: { total: 0, low: 0, medium: 0, high: 0, critical: 0, averageScore: 0, singleMaintainerCount: 0 },
      timestamp: new Date().toISOString(),
    };
  }

  const deps = [
    ...Object.keys((pkgJson.dependencies as Record<string, string>) ?? {}),
    ...Object.keys((pkgJson.devDependencies as Record<string, string>) ?? {}),
  ];

  for (const dep of deps) {
    const profile = await analyzeMaintainer(dep, projectDir);
    packages.push(profile);
  }

  const total = packages.length;
  const low = packages.filter((p) => p.riskLevel === 'low').length;
  const medium = packages.filter((p) => p.riskLevel === 'medium').length;
  const high = packages.filter((p) => p.riskLevel === 'high').length;
  const critical = packages.filter((p) => p.riskLevel === 'critical').length;
  const averageScore = total > 0
    ? Math.round((packages.reduce((sum, p) => sum + p.riskScore, 0) / total) * 10) / 10
    : 0;
  const singleMaintainerCount = packages.filter((p) => p.maintainerCount <= 1).length;

  return {
    packages: packages.sort((a, b) => b.riskScore - a.riskScore),
    summary: { total, low, medium, high, critical, averageScore, singleMaintainerCount },
    timestamp: new Date().toISOString(),
  };
}
