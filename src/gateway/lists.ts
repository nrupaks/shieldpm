/**
 * ShieldPM — Package Allow/Deny List Management
 * Centralized management of approved and banned packages for enterprise use.
 * Stored in shieldpm-lists.json with full audit trail.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────

export interface PackageListEntry {
  name: string;
  version?: string;
  reason: string;
  addedBy: string;
  addedAt: string;
  expiresAt?: string;
}

export interface PackageLists {
  version: 1;
  allowlist: PackageListEntry[];
  denylist: PackageListEntry[];
  updatedAt: string;
}

export type ListCheckResult = {
  allowed: boolean;
  list: 'allowlist' | 'denylist' | 'unlisted';
  entry?: PackageListEntry;
  message: string;
};

// ── Storage ─────────────────────────────────────────────────────────────

const LISTS_FILENAME = 'shieldpm-lists.json';

function emptyLists(): PackageLists {
  return { version: 1, allowlist: [], denylist: [], updatedAt: new Date().toISOString() };
}

export async function loadLists(dir?: string): Promise<PackageLists> {
  const path = join(dir ?? process.cwd(), LISTS_FILENAME);
  try {
    const raw = await readFile(path, 'utf-8');
    return JSON.parse(raw) as PackageLists;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return emptyLists();
    }
    throw err;
  }
}

export async function saveLists(lists: PackageLists, dir?: string): Promise<string> {
  const path = join(dir ?? process.cwd(), LISTS_FILENAME);
  lists.updatedAt = new Date().toISOString();
  await writeFile(path, JSON.stringify(lists, null, 2) + '\n', 'utf-8');
  return path;
}

// ── List Operations ─────────────────────────────────────────────────────

export function addToAllowlist(
  lists: PackageLists,
  name: string,
  reason: string,
  addedBy: string = 'cli',
  version?: string
): PackageLists {
  // Remove from denylist if present
  lists.denylist = lists.denylist.filter((e) => e.name !== name);

  // Don't add duplicates
  if (!lists.allowlist.some((e) => e.name === name)) {
    lists.allowlist.push({
      name,
      version,
      reason,
      addedBy,
      addedAt: new Date().toISOString(),
    });
  }

  return lists;
}

export function addToDenylist(
  lists: PackageLists,
  name: string,
  reason: string,
  addedBy: string = 'cli',
  version?: string
): PackageLists {
  // Remove from allowlist if present
  lists.allowlist = lists.allowlist.filter((e) => e.name !== name);

  // Don't add duplicates
  if (!lists.denylist.some((e) => e.name === name)) {
    lists.denylist.push({
      name,
      version,
      reason,
      addedBy,
      addedAt: new Date().toISOString(),
    });
  }

  return lists;
}

export function removeFromList(lists: PackageLists, name: string): PackageLists {
  lists.allowlist = lists.allowlist.filter((e) => e.name !== name);
  lists.denylist = lists.denylist.filter((e) => e.name !== name);
  return lists;
}

export function checkPackage(lists: PackageLists, name: string, version?: string): ListCheckResult {
  // Check denylist first (deny takes precedence)
  const denied = lists.denylist.find((e) => {
    if (e.name !== name) return false;
    // Check expiry
    if (e.expiresAt && new Date(e.expiresAt) < new Date()) return false;
    // Check version constraint
    if (e.version && version && e.version !== version) return false;
    return true;
  });

  if (denied) {
    return {
      allowed: false,
      list: 'denylist',
      entry: denied,
      message: `"${name}" is on the deny list: ${denied.reason}`,
    };
  }

  // Check allowlist
  const allowed = lists.allowlist.find((e) => {
    if (e.name !== name) return false;
    if (e.expiresAt && new Date(e.expiresAt) < new Date()) return false;
    if (e.version && version && e.version !== version) return false;
    return true;
  });

  if (allowed) {
    return {
      allowed: true,
      list: 'allowlist',
      entry: allowed,
      message: `"${name}" is on the allow list: ${allowed.reason}`,
    };
  }

  return {
    allowed: true,
    list: 'unlisted',
    message: `"${name}" is not on any list (allowed by default)`,
  };
}

export function checkMultiplePackages(
  lists: PackageLists,
  packages: Array<{ name: string; version?: string }>
): Map<string, ListCheckResult> {
  const results = new Map<string, ListCheckResult>();
  for (const pkg of packages) {
    results.set(pkg.name, checkPackage(lists, pkg.name, pkg.version));
  }
  return results;
}

export function getListStats(lists: PackageLists): {
  allowlistCount: number;
  denylistCount: number;
  expiredCount: number;
} {
  const now = new Date();
  let expiredCount = 0;

  for (const entry of [...lists.allowlist, ...lists.denylist]) {
    if (entry.expiresAt && new Date(entry.expiresAt) < now) {
      expiredCount++;
    }
  }

  return {
    allowlistCount: lists.allowlist.length,
    denylistCount: lists.denylist.length,
    expiredCount,
  };
}
