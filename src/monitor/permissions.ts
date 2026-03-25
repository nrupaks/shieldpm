/**
 * ShieldPM — Permission Manifest System
 * Defines, loads, validates, and generates shieldpm.json permission manifests.
 */

import { readFile, writeFile, readdir, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { analyzePackage } from '../analyzer/static.js';

// ── Types ────────────────────────────────────────────────────────────────

export interface PackagePermissions {
  /** Allowed network destinations (glob patterns), or false to block all */
  net: string[] | false;
  /** Allowed filesystem paths (relative or absolute), or false to block all */
  fs: string[] | false;
  /** Whether native/C++ addons are allowed */
  native?: boolean;
  /** Whether child_process spawning is allowed */
  exec?: boolean;
  /** Whether environment variable access is allowed */
  env?: string[] | boolean;
}

export interface PermissionManifest {
  /** Manifest format version */
  version: 1;
  /** Per-package permission declarations */
  permissions: Record<string, PackagePermissions>;
}

export type ResourceType = 'net' | 'fs' | 'native' | 'exec' | 'env';

export interface AccessCheck {
  allowed: boolean;
  rule: string;
  details: string;
}

// ── Default manifest path ────────────────────────────────────────────────

const MANIFEST_FILENAME = 'shieldpm.json';

function resolveManifestPath(dir?: string): string {
  return join(dir ?? process.cwd(), MANIFEST_FILENAME);
}

// ── Load / Save ──────────────────────────────────────────────────────────

/**
 * Load the permission manifest from disk.
 */
export async function loadManifest(dir?: string): Promise<PermissionManifest | null> {
  const path = resolveManifestPath(dir);
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed = JSON.parse(raw);

    // Basic shape validation
    if (!parsed.permissions || typeof parsed.permissions !== 'object') {
      throw new Error('Invalid manifest: missing "permissions" object');
    }

    return {
      version: parsed.version ?? 1,
      permissions: parsed.permissions,
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return null; // No manifest yet
    }
    throw err;
  }
}

/**
 * Save a permission manifest to disk.
 */
export async function saveManifest(manifest: PermissionManifest, dir?: string): Promise<string> {
  const path = resolveManifestPath(dir);
  const json = JSON.stringify(manifest, null, 2) + '\n';
  await writeFile(path, json, 'utf-8');
  return path;
}

// ── Access validation ────────────────────────────────────────────────────

/**
 * Check whether a package is allowed to access a resource.
 */
export function validateAccess(
  manifest: PermissionManifest,
  packageName: string,
  resource: ResourceType,
  target?: string
): AccessCheck {
  const perms = manifest.permissions[packageName];

  // No entry in manifest — default deny
  if (!perms) {
    return {
      allowed: false,
      rule: 'no-manifest-entry',
      details: `Package "${packageName}" has no entry in the permission manifest`,
    };
  }

  switch (resource) {
    case 'net': {
      if (perms.net === false) {
        return {
          allowed: false,
          rule: 'net-blocked',
          details: `Network access is blocked for "${packageName}"`,
        };
      }
      if (!target) {
        return {
          allowed: Array.isArray(perms.net) && perms.net.length > 0,
          rule: 'net-general',
          details: Array.isArray(perms.net)
            ? `Network allowed to: ${perms.net.join(', ')}`
            : 'Network access not configured',
        };
      }
      // Check target against allowed patterns
      const allowed = matchesAnyPattern(target, perms.net);
      return {
        allowed,
        rule: allowed ? 'net-allowed' : 'net-denied',
        details: allowed
          ? `"${target}" matches allowed network pattern`
          : `"${target}" does not match any allowed network pattern for "${packageName}"`,
      };
    }

    case 'fs': {
      if (perms.fs === false) {
        return {
          allowed: false,
          rule: 'fs-blocked',
          details: `Filesystem access is blocked for "${packageName}"`,
        };
      }
      if (!target) {
        return {
          allowed: Array.isArray(perms.fs) && perms.fs.length > 0,
          rule: 'fs-general',
          details: Array.isArray(perms.fs)
            ? `FS allowed in: ${perms.fs.join(', ')}`
            : 'FS access not configured',
        };
      }
      const resolvedTarget = resolve(target);
      const allowed = perms.fs.some((pattern) => {
        const resolvedPattern = resolve(pattern);
        return resolvedTarget.startsWith(resolvedPattern);
      });
      return {
        allowed,
        rule: allowed ? 'fs-allowed' : 'fs-denied',
        details: allowed
          ? `"${target}" is within allowed filesystem paths`
          : `"${target}" is not within any allowed filesystem path for "${packageName}"`,
      };
    }

    case 'native': {
      const allowed = perms.native === true;
      return {
        allowed,
        rule: allowed ? 'native-allowed' : 'native-denied',
        details: allowed
          ? `Native modules allowed for "${packageName}"`
          : `Native modules blocked for "${packageName}"`,
      };
    }

    case 'exec': {
      const allowed = perms.exec === true;
      return {
        allowed,
        rule: allowed ? 'exec-allowed' : 'exec-denied',
        details: allowed
          ? `Process execution allowed for "${packageName}"`
          : `Process execution blocked for "${packageName}"`,
      };
    }

    case 'env': {
      if (perms.env === false || perms.env === undefined) {
        return {
          allowed: false,
          rule: 'env-blocked',
          details: `Environment variable access blocked for "${packageName}"`,
        };
      }
      if (perms.env === true) {
        return {
          allowed: true,
          rule: 'env-allowed-all',
          details: `All environment variables allowed for "${packageName}"`,
        };
      }
      if (!target) {
        return {
          allowed: true,
          rule: 'env-general',
          details: `Env access allowed for: ${perms.env.join(', ')}`,
        };
      }
      const allowed = perms.env.includes(target);
      return {
        allowed,
        rule: allowed ? 'env-allowed' : 'env-denied',
        details: allowed
          ? `Env var "${target}" is allowed for "${packageName}"`
          : `Env var "${target}" is not allowed for "${packageName}"`,
      };
    }

    default:
      return {
        allowed: false,
        rule: 'unknown-resource',
        details: `Unknown resource type: ${resource}`,
      };
  }
}

// ── Pattern matching ─────────────────────────────────────────────────────

/**
 * Match a string against an array of glob-like patterns.
 * Supports: * (any), *.domain.com, exact match.
 */
function matchesAnyPattern(value: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern === '*') return true;

    // Convert glob pattern to regex
    const regexStr = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*');
    const regex = new RegExp(`^${regexStr}$`, 'i');

    if (regex.test(value)) return true;
  }
  return false;
}

// ── Manifest generation ──────────────────────────────────────────────────

/**
 * Auto-generate a permission manifest by scanning installed packages.
 */
export async function generateManifest(projectDir: string): Promise<PermissionManifest> {
  const manifest: PermissionManifest = {
    version: 1,
    permissions: {},
  };

  const nodeModules = join(projectDir, 'node_modules');
  let entries: string[];

  try {
    entries = await readdir(nodeModules);
  } catch {
    return manifest; // No node_modules
  }

  // Collect package directories (including scoped packages)
  const packageDirs: { name: string; dir: string }[] = [];

  for (const entry of entries) {
    if (entry.startsWith('.')) continue;

    const fullPath = join(nodeModules, entry);
    const entryStat = await stat(fullPath).catch(() => null);
    if (!entryStat?.isDirectory()) continue;

    if (entry.startsWith('@')) {
      // Scoped package — look one level deeper
      const scopedEntries = await readdir(fullPath).catch(() => [] as string[]);
      for (const scopedEntry of scopedEntries) {
        const scopedPath = join(fullPath, scopedEntry);
        const scopedStat = await stat(scopedPath).catch(() => null);
        if (scopedStat?.isDirectory()) {
          packageDirs.push({ name: `${entry}/${scopedEntry}`, dir: scopedPath });
        }
      }
    } else {
      packageDirs.push({ name: entry, dir: fullPath });
    }
  }

  // Analyze each package and build permissions
  for (const { name, dir } of packageDirs) {
    const report = await analyzePackage(dir);

    const perms: PackagePermissions = {
      net: false,
      fs: false,
    };

    // If the package uses network, allow it (but default to restrictive)
    if (report.categoryCounts['network']) {
      perms.net = []; // User must fill in allowed destinations
    }

    // If the package uses filesystem
    if (report.categoryCounts['filesystem']) {
      perms.fs = []; // User must fill in allowed paths
    }

    // If the package uses child_process
    if (report.categoryCounts['process']) {
      perms.exec = false; // Default deny, user opts in
    }

    // If the package accesses env
    if (report.categoryCounts['environment']) {
      perms.env = []; // User must fill in allowed vars
    }

    manifest.permissions[name] = perms;
  }

  return manifest;
}
