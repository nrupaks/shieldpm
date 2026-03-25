/**
 * ShieldPM — Dependency Diff
 * Compare two states of package-lock.json to detect meaningful changes
 * in the dependency tree — new packages, version bumps, and red flags.
 */

import { readFile } from 'node:fs/promises';

// ── Types ────────────────────────────────────────────────────────────────

export interface LockPackageInfo {
  version: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  hasInstallScript?: boolean;
  hasBin?: boolean;
}

export interface PackageDelta {
  name: string;
  type: 'added' | 'removed' | 'changed';
  oldVersion?: string;
  newVersion?: string;
  /** Significant changes detected */
  flags: DeltaFlag[];
}

export interface DeltaFlag {
  type: 'new-install-script' | 'new-native-module' | 'new-network-dep' | 'major-bump' |
        'new-dependency' | 'removed-dependency' | 'version-downgrade' | 'new-bin';
  message: string;
}

export interface DependencyDiffReport {
  /** Total packages in the old lock */
  oldPackageCount: number;
  /** Total packages in the new lock */
  newPackageCount: number;
  /** Added packages */
  added: PackageDelta[];
  /** Removed packages */
  removed: PackageDelta[];
  /** Changed packages */
  changed: PackageDelta[];
  /** High-level summary */
  summary: string;
  /** Red flags found */
  flags: DeltaFlag[];
}

// ── Lock file parsing ────────────────────────────────────────────────────

interface LockfileV2 {
  lockfileVersion?: number;
  packages?: Record<string, LockPackageInfo>;
  dependencies?: Record<string, LockPackageInfo>;
}

function parseLockPackages(lockContent: string): Map<string, LockPackageInfo> {
  const lock: LockfileV2 = JSON.parse(lockContent);
  const packages = new Map<string, LockPackageInfo>();

  if (lock.packages) {
    // v2/v3 format: keys are "node_modules/<name>"
    for (const [key, info] of Object.entries(lock.packages)) {
      if (key === '') continue; // Root package
      const name = key.replace(/^node_modules\//, '');
      // Skip nested node_modules
      if (name.includes('node_modules/')) continue;
      packages.set(name, info);
    }
  } else if (lock.dependencies) {
    // v1 format
    for (const [name, info] of Object.entries(lock.dependencies)) {
      packages.set(name, info);
    }
  }

  return packages;
}

// ── Known network-capable packages ───────────────────────────────────────

const NETWORK_PACKAGES = new Set([
  'node-fetch', 'axios', 'got', 'request', 'superagent', 'undici',
  'http-proxy', 'http-proxy-agent', 'https-proxy-agent', 'socks-proxy-agent',
  'socket.io', 'ws', 'websocket', 'net', 'dgram',
]);

const NATIVE_PACKAGES = new Set([
  'node-gyp', 'node-pre-gyp', 'prebuild-install', 'nan', 'napi',
  'sharp', 'bcrypt', 'better-sqlite3', 'canvas', 'grpc',
  'sqlite3', 'pg-native', 'libxmljs',
]);

// ── Version comparison ───────────────────────────────────────────────────

function parseSemver(version: string): { major: number; minor: number; patch: number } | null {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
  };
}

function isMajorBump(oldVer: string, newVer: string): boolean {
  const o = parseSemver(oldVer);
  const n = parseSemver(newVer);
  if (!o || !n) return false;
  return n.major > o.major;
}

function isDowngrade(oldVer: string, newVer: string): boolean {
  const o = parseSemver(oldVer);
  const n = parseSemver(newVer);
  if (!o || !n) return false;
  if (n.major < o.major) return true;
  if (n.major === o.major && n.minor < o.minor) return true;
  if (n.major === o.major && n.minor === o.minor && n.patch < o.patch) return true;
  return false;
}

// ── Diff computation ─────────────────────────────────────────────────────

function computeFlags(
  name: string,
  oldInfo: LockPackageInfo | undefined,
  newInfo: LockPackageInfo | undefined
): DeltaFlag[] {
  const flags: DeltaFlag[] = [];

  if (newInfo && !oldInfo) {
    // Newly added package
    if (newInfo.hasInstallScript) {
      flags.push({
        type: 'new-install-script',
        message: `New package "${name}" has install scripts`,
      });
    }
    if (NATIVE_PACKAGES.has(name)) {
      flags.push({
        type: 'new-native-module',
        message: `New package "${name}" is a native module`,
      });
    }
    if (NETWORK_PACKAGES.has(name)) {
      flags.push({
        type: 'new-network-dep',
        message: `New package "${name}" has network capabilities`,
      });
    }
    if (newInfo.hasBin) {
      flags.push({
        type: 'new-bin',
        message: `New package "${name}" installs binaries`,
      });
    }
  }

  if (oldInfo && newInfo) {
    // Version change checks
    if (oldInfo.version && newInfo.version) {
      if (isMajorBump(oldInfo.version, newInfo.version)) {
        flags.push({
          type: 'major-bump',
          message: `"${name}" major version bump: ${oldInfo.version} -> ${newInfo.version}`,
        });
      }
      if (isDowngrade(oldInfo.version, newInfo.version)) {
        flags.push({
          type: 'version-downgrade',
          message: `"${name}" version downgrade: ${oldInfo.version} -> ${newInfo.version}`,
        });
      }
    }

    // New install script added
    if (!oldInfo.hasInstallScript && newInfo.hasInstallScript) {
      flags.push({
        type: 'new-install-script',
        message: `"${name}" added install scripts in ${newInfo.version}`,
      });
    }

    // New sub-dependencies
    const oldDeps = new Set(Object.keys(oldInfo.dependencies ?? {}));
    const newDeps = Object.keys(newInfo.dependencies ?? {});
    for (const dep of newDeps) {
      if (!oldDeps.has(dep)) {
        flags.push({
          type: 'new-dependency',
          message: `"${name}" added new dependency "${dep}"`,
        });
      }
    }
  }

  return flags;
}

/**
 * Compare two package-lock.json contents and produce a diff report.
 */
export function diffLockfiles(
  oldLockContent: string,
  newLockContent: string
): DependencyDiffReport {
  const oldPackages = parseLockPackages(oldLockContent);
  const newPackages = parseLockPackages(newLockContent);

  const added: PackageDelta[] = [];
  const removed: PackageDelta[] = [];
  const changed: PackageDelta[] = [];
  const allFlags: DeltaFlag[] = [];

  // Find added and changed
  for (const [name, newInfo] of newPackages) {
    const oldInfo = oldPackages.get(name);

    if (!oldInfo) {
      const flags = computeFlags(name, undefined, newInfo);
      added.push({
        name,
        type: 'added',
        newVersion: newInfo.version,
        flags,
      });
      allFlags.push(...flags);
    } else if (oldInfo.version !== newInfo.version) {
      const flags = computeFlags(name, oldInfo, newInfo);
      changed.push({
        name,
        type: 'changed',
        oldVersion: oldInfo.version,
        newVersion: newInfo.version,
        flags,
      });
      allFlags.push(...flags);
    }
  }

  // Find removed
  for (const [name, oldInfo] of oldPackages) {
    if (!newPackages.has(name)) {
      removed.push({
        name,
        type: 'removed',
        oldVersion: oldInfo.version,
        flags: [],
      });
    }
  }

  // Sort alphabetically
  added.sort((a, b) => a.name.localeCompare(b.name));
  removed.sort((a, b) => a.name.localeCompare(b.name));
  changed.sort((a, b) => a.name.localeCompare(b.name));

  // Summary
  const parts: string[] = [];
  if (added.length > 0) parts.push(`${added.length} added`);
  if (removed.length > 0) parts.push(`${removed.length} removed`);
  if (changed.length > 0) parts.push(`${changed.length} changed`);
  if (allFlags.length > 0) parts.push(`${allFlags.length} flags`);

  const summary = parts.length > 0
    ? `Dependency changes: ${parts.join(', ')}`
    : 'No dependency changes';

  return {
    oldPackageCount: oldPackages.size,
    newPackageCount: newPackages.size,
    added,
    removed,
    changed,
    summary,
    flags: allFlags,
  };
}

/**
 * Load and diff two package-lock.json files from disk.
 */
export async function diffLockfilesByPath(
  oldPath: string,
  newPath: string
): Promise<DependencyDiffReport> {
  const [oldContent, newContent] = await Promise.all([
    readFile(oldPath, 'utf-8'),
    readFile(newPath, 'utf-8'),
  ]);
  return diffLockfiles(oldContent, newContent);
}
