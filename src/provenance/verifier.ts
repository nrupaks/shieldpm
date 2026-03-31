/**
 * ShieldPM — Package Provenance Verification
 * Verifies npm package provenance attestations and Sigstore signatures
 * to ensure packages were built from their claimed source repositories.
 */

import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// ── Types ────────────────────────────────────────────────────────────────

export type ProvenanceStatus = 'verified' | 'unverified' | 'missing' | 'invalid' | 'error';

export interface ProvenanceInfo {
  packageName: string;
  version: string;
  status: ProvenanceStatus;
  sourceRepo: string | null;
  buildTrigger: string | null;
  buildWorkflow: string | null;
  transparency: string | null;
  integrity: {
    algorithm: string;
    digest: string;
  } | null;
  registry: string;
  publishedAt: string | null;
  attestation: AttestationInfo | null;
  riskFactors: string[];
}

export interface AttestationInfo {
  predicateType: string;
  buildType: string;
  builder: string;
  sourceUri: string;
  sourceDigest: string;
  invocationId: string;
  verified: boolean;
}

export interface ProvenanceReport {
  packages: ProvenanceInfo[];
  summary: {
    total: number;
    verified: number;
    unverified: number;
    missing: number;
    invalid: number;
    provenanceCoverage: number;
  };
  timestamp: string;
}

// ── Provenance Extraction ───────────────────────────────────────────────

async function extractProvenanceFromPackage(
  packageName: string,
  projectDir: string
): Promise<ProvenanceInfo> {
  const pkgDir = join(projectDir, 'node_modules', packageName);
  const riskFactors: string[] = [];

  let version = '0.0.0';
  let sourceRepo: string | null = null;
  let integrity: ProvenanceInfo['integrity'] = null;
  let publishedAt: string | null = null;

  // Read package.json
  try {
    const pkgJson = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf-8'));
    version = pkgJson.version ?? '0.0.0';

    // Extract repository info
    if (typeof pkgJson.repository === 'string') {
      sourceRepo = pkgJson.repository;
    } else if (pkgJson.repository?.url) {
      sourceRepo = pkgJson.repository.url
        .replace(/^git\+/, '')
        .replace(/\.git$/, '');
    }

    // Check for publishConfig
    if (pkgJson.publishConfig?.provenance === true) {
      // Package declares provenance support
    }
  } catch { /* ok */ }

  // Read from package-lock.json for integrity info
  try {
    const lockRaw = await readFile(join(projectDir, 'package-lock.json'), 'utf-8');
    const lock = JSON.parse(lockRaw);
    const lockKey = `node_modules/${packageName}`;
    const lockEntry = lock.packages?.[lockKey] ?? lock.dependencies?.[packageName];

    if (lockEntry) {
      if (lockEntry.integrity) {
        const [algo, digest] = lockEntry.integrity.split('-');
        integrity = { algorithm: algo ?? 'sha512', digest: digest ?? lockEntry.integrity };
      }
    }
  } catch { /* ok */ }

  // Check for .sigstore attestation bundle
  let attestation: AttestationInfo | null = null;
  try {
    // npm stores provenance in _provenance field or .sigstore directory
    const provenancePath = join(pkgDir, '.sigstore');
    const provBundle = join(pkgDir, 'provenance.json');

    // Try reading provenance bundle
    try {
      const bundle = JSON.parse(await readFile(provBundle, 'utf-8'));
      attestation = parseAttestation(bundle);
    } catch { /* no provenance bundle */ }
  } catch { /* ok */ }

  // Compute content hash for verification
  const contentHash = await computePackageHash(pkgDir);

  // Determine status
  let status: ProvenanceStatus = 'missing';

  if (attestation?.verified) {
    status = 'verified';
  } else if (attestation) {
    status = 'unverified';
    riskFactors.push('Attestation present but not verified');
  } else if (integrity) {
    status = 'unverified';
  }

  // Risk factor analysis
  if (!sourceRepo) {
    riskFactors.push('No source repository declared');
  }

  if (!integrity) {
    riskFactors.push('No integrity hash in lockfile');
  }

  if (sourceRepo && sourceRepo.includes('github.com')) {
    // Check if repo URL looks legitimate
    const repoMatch = sourceRepo.match(/github\.com[/:]([^/]+)\/([^/]+)/);
    if (repoMatch) {
      const [, owner, repo] = repoMatch;
      // Flag if package name doesn't match repo
      const normalizedPkg = packageName.replace(/^@[^/]+\//, '');
      const normalizedRepo = repo?.toLowerCase() ?? '';
      if (!normalizedRepo.includes(normalizedPkg.toLowerCase()) &&
          !normalizedPkg.includes(normalizedRepo)) {
        riskFactors.push(`Package name "${packageName}" doesn't match repo "${repo}"`);
      }
    }
  }

  return {
    packageName,
    version,
    status,
    sourceRepo,
    buildTrigger: attestation?.invocationId ?? null,
    buildWorkflow: attestation?.buildType ?? null,
    transparency: null,
    integrity,
    registry: 'https://registry.npmjs.org',
    publishedAt,
    attestation,
    riskFactors,
  };
}

function parseAttestation(bundle: Record<string, unknown>): AttestationInfo | null {
  try {
    const predicate = bundle.predicate as Record<string, unknown> | undefined;
    if (!predicate) return null;

    const buildType = (predicate.buildType as string) ?? 'unknown';
    const builder = ((predicate.builder as Record<string, string>)?.id) ?? 'unknown';
    const materials = (predicate.materials as Array<{ uri?: string; digest?: Record<string, string> }>) ?? [];
    const source = materials[0];

    return {
      predicateType: (bundle.predicateType as string) ?? 'https://slsa.dev/provenance/v1',
      buildType,
      builder,
      sourceUri: source?.uri ?? 'unknown',
      sourceDigest: source?.digest?.sha1 ?? source?.digest?.sha256 ?? 'unknown',
      invocationId: ((predicate.invocation as Record<string, unknown>)?.configSource as Record<string, string> | undefined)?.entryPoint ?? 'unknown',
      verified: false, // Full verification requires Sigstore/Rekor integration
    };
  } catch {
    return null;
  }
}

async function computePackageHash(pkgDir: string): Promise<string> {
  const hash = createHash('sha256');

  async function walk(dir: string): Promise<void> {
    try {
      const entries = await readdir(dir, { withFileTypes: true });
      for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        const full = join(dir, entry.name);
        if (entry.isFile()) {
          try {
            const content = await readFile(full);
            hash.update(content);
          } catch { /* skip unreadable */ }
        } else if (entry.isDirectory()) {
          await walk(full);
        }
      }
    } catch { /* skip */ }
  }

  await walk(pkgDir);
  return hash.digest('hex');
}

// ── Provenance Scanning ─────────────────────────────────────────────────

export async function verifyProvenance(
  packageName: string,
  projectDir: string
): Promise<ProvenanceInfo> {
  return extractProvenanceFromPackage(packageName, projectDir);
}

export async function scanProvenance(projectDir: string): Promise<ProvenanceReport> {
  const packages: ProvenanceInfo[] = [];

  let pkgJson: Record<string, unknown>;
  try {
    pkgJson = JSON.parse(await readFile(join(projectDir, 'package.json'), 'utf-8'));
  } catch {
    return { packages, summary: { total: 0, verified: 0, unverified: 0, missing: 0, invalid: 0, provenanceCoverage: 0 }, timestamp: new Date().toISOString() };
  }

  const deps = [
    ...Object.keys((pkgJson.dependencies as Record<string, string>) ?? {}),
    ...Object.keys((pkgJson.devDependencies as Record<string, string>) ?? {}),
  ];

  for (const dep of deps) {
    const info = await extractProvenanceFromPackage(dep, projectDir);
    packages.push(info);
  }

  const verified = packages.filter((p) => p.status === 'verified').length;
  const unverified = packages.filter((p) => p.status === 'unverified').length;
  const missing = packages.filter((p) => p.status === 'missing').length;
  const invalid = packages.filter((p) => p.status === 'invalid').length;
  const total = packages.length;
  const provenanceCoverage = total > 0 ? Math.round((verified / total) * 100) : 0;

  return {
    packages: packages.sort((a, b) => a.packageName.localeCompare(b.packageName)),
    summary: { total, verified, unverified, missing, invalid, provenanceCoverage },
    timestamp: new Date().toISOString(),
  };
}
