/**
 * ShieldPM — SBOM Generator
 * Generates Software Bill of Materials in CycloneDX and SPDX formats.
 * Parses package-lock.json and package.json to enumerate all dependencies.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// ── Types ────────────────────────────────────────────────────────────────

export type SBOMFormat = 'cyclonedx' | 'spdx';

export interface SBOMComponent {
  name: string;
  version: string;
  purl: string;
  license: string | null;
  description: string;
  author: string;
  integrity: string;
  resolved: string;
  dependencies: string[];
  scope: 'required' | 'optional' | 'dev';
}

export interface SBOMDocument {
  format: SBOMFormat;
  specVersion: string;
  serialNumber: string;
  timestamp: string;
  tool: { name: string; version: string };
  subject: { name: string; version: string };
  components: SBOMComponent[];
  dependencies: Array<{ ref: string; dependsOn: string[] }>;
  totalComponents: number;
}

// ── Package-lock parsing ────────────────────────────────────────────────

interface LockEntry {
  version: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  dev?: boolean;
  optional?: boolean;
  license?: string;
}

async function parseLockfile(projectDir: string): Promise<Map<string, LockEntry>> {
  const lockPath = join(projectDir, 'package-lock.json');
  const packages = new Map<string, LockEntry>();

  try {
    const raw = JSON.parse(await readFile(lockPath, 'utf-8'));

    if (raw.packages) {
      for (const [key, info] of Object.entries(raw.packages)) {
        if (key === '') continue;
        const name = key.replace(/^node_modules\//, '');
        if (name.includes('node_modules/')) continue;
        packages.set(name, info as LockEntry);
      }
    } else if (raw.dependencies) {
      for (const [name, info] of Object.entries(raw.dependencies)) {
        packages.set(name, info as LockEntry);
      }
    }
  } catch {
    // Fall back to scanning node_modules
  }

  return packages;
}

async function readPackageJson(dir: string): Promise<Record<string, unknown> | null> {
  try {
    return JSON.parse(await readFile(join(dir, 'package.json'), 'utf-8'));
  } catch {
    return null;
  }
}

function makePurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const [scope, pkg] = name.split('/');
    return `pkg:npm/${encodeURIComponent(scope)}/${pkg}@${version}`;
  }
  return `pkg:npm/${name}@${version}`;
}

function generateSerialNumber(): string {
  const bytes = createHash('sha256')
    .update(Date.now().toString() + Math.random().toString())
    .digest('hex')
    .slice(0, 32);
  return `urn:uuid:${bytes.slice(0, 8)}-${bytes.slice(8, 12)}-${bytes.slice(12, 16)}-${bytes.slice(16, 20)}-${bytes.slice(20, 32)}`;
}

// ── SBOM Generation ─────────────────────────────────────────────────────

export async function generateSBOM(
  projectDir: string,
  format: SBOMFormat = 'cyclonedx'
): Promise<SBOMDocument> {
  const pkgJson = await readPackageJson(projectDir);
  const projectName = (pkgJson?.name as string) ?? 'unknown';
  const projectVersion = (pkgJson?.version as string) ?? '0.0.0';
  const prodDeps = new Set(Object.keys((pkgJson?.dependencies as Record<string, string>) ?? {}));
  const devDeps = new Set(Object.keys((pkgJson?.devDependencies as Record<string, string>) ?? {}));

  const lockEntries = await parseLockfile(projectDir);
  const components: SBOMComponent[] = [];
  const depGraph: Array<{ ref: string; dependsOn: string[] }> = [];

  for (const [name, entry] of lockEntries) {
    // Read individual package.json for extra metadata
    let pkgMeta: Record<string, unknown> | null = null;
    try {
      pkgMeta = await readPackageJson(join(projectDir, 'node_modules', name));
    } catch { /* ok */ }

    const license = (pkgMeta?.license as string)
      ?? (entry.license as string)
      ?? null;

    const scope: SBOMComponent['scope'] = entry.dev
      ? 'dev'
      : entry.optional
        ? 'optional'
        : devDeps.has(name)
          ? 'dev'
          : 'required';

    const component: SBOMComponent = {
      name,
      version: entry.version,
      purl: makePurl(name, entry.version),
      license,
      description: (pkgMeta?.description as string) ?? '',
      author: typeof pkgMeta?.author === 'string'
        ? pkgMeta.author
        : (pkgMeta?.author as { name?: string })?.name ?? '',
      integrity: entry.integrity ?? '',
      resolved: entry.resolved ?? '',
      dependencies: Object.keys(entry.dependencies ?? {}),
      scope,
    };

    components.push(component);

    depGraph.push({
      ref: component.purl,
      dependsOn: Object.entries(entry.dependencies ?? {}).map(
        ([dep]) => {
          const depEntry = lockEntries.get(dep);
          return makePurl(dep, depEntry?.version ?? '0.0.0');
        }
      ),
    });
  }

  return {
    format,
    specVersion: format === 'cyclonedx' ? '1.5' : 'SPDX-2.3',
    serialNumber: generateSerialNumber(),
    timestamp: new Date().toISOString(),
    tool: { name: 'shieldpm', version: '0.3.0' },
    subject: { name: projectName, version: projectVersion },
    components: components.sort((a, b) => a.name.localeCompare(b.name)),
    dependencies: depGraph,
    totalComponents: components.length,
  };
}

// ── Format Serializers ──────────────────────────────────────────────────

export function toCycloneDX(doc: SBOMDocument): object {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: doc.serialNumber,
    version: 1,
    metadata: {
      timestamp: doc.timestamp,
      tools: [{ vendor: 'shieldpm', name: doc.tool.name, version: doc.tool.version }],
      component: {
        type: 'application',
        name: doc.subject.name,
        version: doc.subject.version,
        'bom-ref': `pkg:npm/${doc.subject.name}@${doc.subject.version}`,
      },
    },
    components: doc.components.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      purl: c.purl,
      'bom-ref': c.purl,
      scope: c.scope,
      ...(c.license ? {
        licenses: [{ license: { id: normalizeLicenseId(c.license) } }],
      } : {}),
      ...(c.description ? { description: c.description } : {}),
      ...(c.author ? { author: c.author } : {}),
      ...(c.integrity ? {
        hashes: [{ alg: c.integrity.startsWith('sha512') ? 'SHA-512' : 'SHA-256', content: c.integrity.split('-')[1] ?? c.integrity }],
      } : {}),
      externalReferences: c.resolved ? [{ type: 'distribution', url: c.resolved }] : [],
    })),
    dependencies: doc.dependencies.map((d) => ({
      ref: d.ref,
      dependsOn: d.dependsOn,
    })),
  };
}

export function toSPDX(doc: SBOMDocument): object {
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${doc.subject.name}-${doc.subject.version}`,
    documentNamespace: `https://shieldpm.dev/spdx/${doc.subject.name}/${doc.serialNumber}`,
    creationInfo: {
      created: doc.timestamp,
      creators: [`Tool: ${doc.tool.name}-${doc.tool.version}`],
      licenseListVersion: '3.22',
    },
    packages: doc.components.map((c, i) => ({
      SPDXID: `SPDXRef-Package-${i + 1}`,
      name: c.name,
      versionInfo: c.version,
      downloadLocation: c.resolved || 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: c.license ? normalizeLicenseId(c.license) : 'NOASSERTION',
      licenseDeclared: c.license ? normalizeLicenseId(c.license) : 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: c.purl,
      }],
      ...(c.description ? { description: c.description } : {}),
      ...(c.integrity ? {
        checksums: [{
          algorithm: c.integrity.startsWith('sha512') ? 'SHA512' : 'SHA256',
          checksumValue: c.integrity.split('-')[1] ?? c.integrity,
        }],
      } : {}),
    })),
    relationships: doc.dependencies.flatMap((d, i) =>
      d.dependsOn.map((dep) => ({
        spdxElementId: `SPDXRef-Package-${i + 1}`,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: dep,
      }))
    ),
  };
}

// ── License ID normalization ────────────────────────────────────────────

const LICENSE_MAP: Record<string, string> = {
  'mit': 'MIT',
  'isc': 'ISC',
  'bsd-2-clause': 'BSD-2-Clause',
  'bsd-3-clause': 'BSD-3-Clause',
  'apache-2.0': 'Apache-2.0',
  'apache 2.0': 'Apache-2.0',
  'gpl-2.0': 'GPL-2.0-only',
  'gpl-3.0': 'GPL-3.0-only',
  'lgpl-2.1': 'LGPL-2.1-only',
  'lgpl-3.0': 'LGPL-3.0-only',
  'mpl-2.0': 'MPL-2.0',
  'unlicense': 'Unlicense',
  'cc0-1.0': 'CC0-1.0',
  '0bsd': '0BSD',
  'artistic-2.0': 'Artistic-2.0',
  'bsl-1.0': 'BSL-1.0',
  'wtfpl': 'WTFPL',
};

function normalizeLicenseId(raw: string): string {
  const lower = raw.toLowerCase().trim();
  return LICENSE_MAP[lower] ?? raw;
}

export { normalizeLicenseId };
