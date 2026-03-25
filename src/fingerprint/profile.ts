/**
 * ShieldPM — Behavioral Fingerprinting
 * Creates and compares behavioral profiles for packages to detect
 * unexpected changes between versions.
 */

import { readFile, writeFile, readdir, stat, mkdir } from 'node:fs/promises';
import { join, extname, relative } from 'node:path';
import { createHash } from 'node:crypto';

// ── Types ────────────────────────────────────────────────────────────────

export interface BehaviorProfile {
  /** Package name */
  name: string;
  /** Package version */
  version: string;
  /** ISO timestamp of when the profile was generated */
  generatedAt: string;
  /** SHA-256 hash of all .js file contents concatenated */
  contentHash: string;
  /** Individual file hashes */
  fileHashes: Record<string, string>;
  /** All require() and import statements found */
  imports: string[];
  /** Native module bindings (e.g., .node files, node-gyp) */
  nativeBindings: string[];
  /** Network endpoints parsed from source */
  networkEndpoints: string[];
  /** Filesystem paths parsed from source */
  fsPaths: string[];
  /** Total file count */
  fileCount: number;
  /** Total size in bytes */
  totalSize: number;
}

export interface ProfileDiff {
  /** Newly added imports */
  addedImports: string[];
  /** Removed imports */
  removedImports: string[];
  /** Newly added network endpoints */
  addedNetworkEndpoints: string[];
  /** Removed network endpoints */
  removedNetworkEndpoints: string[];
  /** New filesystem paths */
  addedFsPaths: string[];
  /** Removed filesystem paths */
  removedFsPaths: string[];
  /** New native bindings */
  addedNativeBindings: string[];
  /** Removed native bindings */
  removedNativeBindings: string[];
  /** Files added */
  addedFiles: string[];
  /** Files removed */
  removedFiles: string[];
  /** Files with changed content */
  changedFiles: string[];
  /** Whether the overall content hash changed */
  contentHashChanged: boolean;
  /** Human-readable summary */
  summary: string;
}

// ── Profile storage ──────────────────────────────────────────────────────

const PROFILE_DIR = '.shieldpm/profiles';

function profilePath(baseDir: string, name: string, version: string): string {
  return join(baseDir, PROFILE_DIR, `${name.replace('/', '__')}@${version}.json`);
}

export async function saveProfile(baseDir: string, profile: BehaviorProfile): Promise<string> {
  const dir = join(baseDir, PROFILE_DIR);
  await mkdir(dir, { recursive: true });

  const path = profilePath(baseDir, profile.name, profile.version);
  await writeFile(path, JSON.stringify(profile, null, 2) + '\n', 'utf-8');
  return path;
}

export async function loadProfile(
  baseDir: string,
  name: string,
  version: string
): Promise<BehaviorProfile | null> {
  const path = profilePath(baseDir, name, version);
  try {
    const raw = await readFile(path, 'utf-8');
    return JSON.parse(raw) as BehaviorProfile;
  } catch {
    return null;
  }
}

// ── Source parsing helpers ────────────────────────────────────────────────

const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'test', 'tests', '__tests__']);

async function collectSourceFiles(dir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(d: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(full);
      } else if (entry.isFile() && JS_EXTENSIONS.has(extname(entry.name))) {
        files.push(full);
      }
    }
  }

  await walk(dir);
  return files.sort();
}

function extractImports(source: string): string[] {
  const imports = new Set<string>();

  // CommonJS require
  const requireRe = /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = requireRe.exec(source)) !== null) {
    imports.add(m[1]);
  }

  // ESM import
  const importRe = /(?:import|export)\s+.*?from\s+['"`]([^'"`]+)['"`]/g;
  while ((m = importRe.exec(source)) !== null) {
    imports.add(m[1]);
  }

  // Dynamic import
  const dynImportRe = /import\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
  while ((m = dynImportRe.exec(source)) !== null) {
    imports.add(m[1]);
  }

  return [...imports].sort();
}

function extractNetworkEndpoints(source: string): string[] {
  const endpoints = new Set<string>();

  // URL literals
  const urlRe = /['"`](https?:\/\/[^'"`\s]+)['"`]/g;
  let m: RegExpExecArray | null;
  while ((m = urlRe.exec(source)) !== null) {
    endpoints.add(m[1]);
  }

  // fetch/http.request with template literals are harder — capture hostname patterns
  const hostRe = /(?:hostname|host)\s*[:=]\s*['"`]([^'"`]+)['"`]/g;
  while ((m = hostRe.exec(source)) !== null) {
    endpoints.add(m[1]);
  }

  return [...endpoints].sort();
}

function extractFsPaths(source: string): string[] {
  const paths = new Set<string>();

  // readFile, writeFile, etc. with string literals
  const fsRe = /(?:readFile|writeFile|readdir|unlink|stat|access|mkdir|rmdir|rename|copyFile|appendFile)\w*\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let m: RegExpExecArray | null;
  while ((m = fsRe.exec(source)) !== null) {
    paths.add(m[1]);
  }

  return [...paths].sort();
}

function extractNativeBindings(files: string[], source: string): string[] {
  const bindings = new Set<string>();

  // .node files
  for (const f of files) {
    if (f.endsWith('.node')) {
      bindings.add(f);
    }
  }

  // require with .node extension
  const nodeReqRe = /require\s*\(\s*['"`]([^'"`]*\.node)['"`]\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = nodeReqRe.exec(source)) !== null) {
    bindings.add(m[1]);
  }

  // node-gyp / node-pre-gyp / prebuild patterns
  if (/binding\.gyp|node-gyp|node-pre-gyp|prebuild-install|napi_/.test(source)) {
    bindings.add('<native-addon>');
  }

  return [...bindings].sort();
}

// ── Profile generation ───────────────────────────────────────────────────

/**
 * Generate a behavioral profile for a package directory.
 */
export async function generateProfile(
  packageDir: string,
  name: string,
  version: string
): Promise<BehaviorProfile> {
  const files = await collectSourceFiles(packageDir);

  const allImports = new Set<string>();
  const allEndpoints = new Set<string>();
  const allFsPaths = new Set<string>();
  const fileHashes: Record<string, string> = {};
  const contentParts: string[] = [];
  let totalSize = 0;
  let allSourceConcat = '';

  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, 'utf-8');
    } catch {
      continue;
    }

    const relPath = relative(packageDir, file);
    const hash = createHash('sha256').update(content).digest('hex');
    fileHashes[relPath] = hash;
    contentParts.push(content);
    totalSize += Buffer.byteLength(content);
    allSourceConcat += content + '\n';

    for (const imp of extractImports(content)) allImports.add(imp);
    for (const ep of extractNetworkEndpoints(content)) allEndpoints.add(ep);
    for (const fp of extractFsPaths(content)) allFsPaths.add(fp);
  }

  const contentHash = createHash('sha256')
    .update(contentParts.join('\n'))
    .digest('hex');

  const nativeBindings = extractNativeBindings(
    files.map((f) => relative(packageDir, f)),
    allSourceConcat
  );

  return {
    name,
    version,
    generatedAt: new Date().toISOString(),
    contentHash,
    fileHashes,
    imports: [...allImports].sort(),
    nativeBindings,
    networkEndpoints: [...allEndpoints].sort(),
    fsPaths: [...allFsPaths].sort(),
    fileCount: files.length,
    totalSize,
  };
}

// ── Profile comparison ───────────────────────────────────────────────────

function arrayDiff<T>(oldArr: T[], newArr: T[]): { added: T[]; removed: T[] } {
  const oldSet = new Set(oldArr);
  const newSet = new Set(newArr);
  return {
    added: newArr.filter((x) => !oldSet.has(x)),
    removed: oldArr.filter((x) => !newSet.has(x)),
  };
}

/**
 * Compare two behavioral profiles and report differences.
 */
export function diffProfiles(oldProfile: BehaviorProfile, newProfile: BehaviorProfile): ProfileDiff {
  const importDiff = arrayDiff(oldProfile.imports, newProfile.imports);
  const netDiff = arrayDiff(oldProfile.networkEndpoints, newProfile.networkEndpoints);
  const fsDiff = arrayDiff(oldProfile.fsPaths, newProfile.fsPaths);
  const nativeDiff = arrayDiff(oldProfile.nativeBindings, newProfile.nativeBindings);

  const oldFiles = Object.keys(oldProfile.fileHashes);
  const newFiles = Object.keys(newProfile.fileHashes);
  const fileDiff = arrayDiff(oldFiles, newFiles);

  const commonFiles = oldFiles.filter((f) => newFiles.includes(f));
  const changedFiles = commonFiles.filter(
    (f) => oldProfile.fileHashes[f] !== newProfile.fileHashes[f]
  );

  const contentHashChanged = oldProfile.contentHash !== newProfile.contentHash;

  // Build summary
  const parts: string[] = [];
  if (fileDiff.added.length > 0) parts.push(`${fileDiff.added.length} files added`);
  if (fileDiff.removed.length > 0) parts.push(`${fileDiff.removed.length} files removed`);
  if (changedFiles.length > 0) parts.push(`${changedFiles.length} files changed`);
  if (importDiff.added.length > 0) parts.push(`${importDiff.added.length} new imports`);
  if (importDiff.removed.length > 0) parts.push(`${importDiff.removed.length} removed imports`);
  if (netDiff.added.length > 0) parts.push(`${netDiff.added.length} new network endpoints`);
  if (nativeDiff.added.length > 0) parts.push(`${nativeDiff.added.length} new native bindings`);

  const summary = parts.length > 0
    ? `Changes: ${parts.join(', ')}`
    : 'No behavioral changes detected';

  return {
    addedImports: importDiff.added,
    removedImports: importDiff.removed,
    addedNetworkEndpoints: netDiff.added,
    removedNetworkEndpoints: netDiff.removed,
    addedFsPaths: fsDiff.added,
    removedFsPaths: fsDiff.removed,
    addedNativeBindings: nativeDiff.added,
    removedNativeBindings: nativeDiff.removed,
    addedFiles: fileDiff.added,
    removedFiles: fileDiff.removed,
    changedFiles,
    contentHashChanged,
    summary,
  };
}
