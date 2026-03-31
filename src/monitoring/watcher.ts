/**
 * ShieldPM — Continuous Monitoring
 * Watches for changes in dependencies, lockfiles, and advisories.
 * Provides background monitoring and alerting capabilities.
 */

import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';

// ── Types ────────────────────────────────────────────────────────────────

export type MonitorEventType =
  | 'lockfile-changed'
  | 'package-added'
  | 'package-removed'
  | 'package-updated'
  | 'risk-increased'
  | 'new-finding'
  | 'manifest-drift'
  | 'policy-violation';

export type AlertSeverity = 'info' | 'warning' | 'critical';

export interface MonitorEvent {
  type: MonitorEventType;
  severity: AlertSeverity;
  timestamp: string;
  packageName?: string;
  message: string;
  details: Record<string, unknown>;
}

export interface MonitorState {
  version: 1;
  lastCheck: string;
  lockfileHash: string;
  packageJsonHash: string;
  packageScores: Record<string, number>;
  packageVersions: Record<string, string>;
  events: MonitorEvent[];
  checksPerformed: number;
}

export interface MonitorConfig {
  watchLockfile: boolean;
  watchPackageJson: boolean;
  alertOnRiskIncrease: boolean;
  riskThreshold: number;
  maxEventsStored: number;
}

export interface MonitorStatus {
  isConfigured: boolean;
  lastCheck: string | null;
  checksPerformed: number;
  recentEvents: MonitorEvent[];
  lockfileHash: string | null;
  trackedPackages: number;
  summary: string;
}

// ── Defaults ────────────────────────────────────────────────────────────

const MONITOR_DIR = '.shieldpm';
const STATE_FILE = 'monitor-state.json';

const DEFAULT_CONFIG: MonitorConfig = {
  watchLockfile: true,
  watchPackageJson: true,
  alertOnRiskIncrease: true,
  riskThreshold: 7,
  maxEventsStored: 100,
};

function emptyState(): MonitorState {
  return {
    version: 1,
    lastCheck: '',
    lockfileHash: '',
    packageJsonHash: '',
    packageScores: {},
    packageVersions: {},
    events: [],
    checksPerformed: 0,
  };
}

// ── State Persistence ───────────────────────────────────────────────────

async function loadState(projectDir: string): Promise<MonitorState> {
  const path = join(projectDir, MONITOR_DIR, STATE_FILE);
  try {
    const raw = await readFile(path, 'utf-8');
    return JSON.parse(raw) as MonitorState;
  } catch {
    return emptyState();
  }
}

async function saveState(projectDir: string, state: MonitorState): Promise<void> {
  const dir = join(projectDir, MONITOR_DIR);
  await mkdir(dir, { recursive: true });
  const path = join(dir, STATE_FILE);
  await writeFile(path, JSON.stringify(state, null, 2) + '\n', 'utf-8');
}

// ── Hash Utilities ──────────────────────────────────────────────────────

async function hashFile(filePath: string): Promise<string> {
  try {
    const content = await readFile(filePath, 'utf-8');
    return createHash('sha256').update(content).digest('hex').slice(0, 16);
  } catch {
    return '';
  }
}

// ── Core Monitoring ─────────────────────────────────────────────────────

export async function runCheck(
  projectDir: string,
  currentScores: Record<string, number> = {},
  config: MonitorConfig = DEFAULT_CONFIG
): Promise<MonitorEvent[]> {
  const state = await loadState(projectDir);
  const events: MonitorEvent[] = [];
  const now = new Date().toISOString();

  // 1. Check lockfile changes
  if (config.watchLockfile) {
    const lockHash = await hashFile(join(projectDir, 'package-lock.json'));
    if (state.lockfileHash && lockHash && lockHash !== state.lockfileHash) {
      events.push({
        type: 'lockfile-changed',
        severity: 'warning',
        timestamp: now,
        message: 'package-lock.json has changed since last check',
        details: { oldHash: state.lockfileHash, newHash: lockHash },
      });
    }
    state.lockfileHash = lockHash;
  }

  // 2. Check package.json changes
  if (config.watchPackageJson) {
    const pkgHash = await hashFile(join(projectDir, 'package.json'));
    if (state.packageJsonHash && pkgHash && pkgHash !== state.packageJsonHash) {
      events.push({
        type: 'lockfile-changed',
        severity: 'info',
        timestamp: now,
        message: 'package.json has changed since last check',
        details: { oldHash: state.packageJsonHash, newHash: pkgHash },
      });
    }
    state.packageJsonHash = pkgHash;
  }

  // 3. Detect new/removed/updated packages
  try {
    const pkgJson = JSON.parse(await readFile(join(projectDir, 'package.json'), 'utf-8'));
    const currentDeps: Record<string, string> = {
      ...(pkgJson.dependencies ?? {}),
      ...(pkgJson.devDependencies ?? {}),
    };

    const oldPkgs = new Set(Object.keys(state.packageVersions));
    const newPkgs = new Set(Object.keys(currentDeps));

    // New packages
    for (const pkg of newPkgs) {
      if (!oldPkgs.has(pkg)) {
        events.push({
          type: 'package-added',
          severity: 'warning',
          timestamp: now,
          packageName: pkg,
          message: `New dependency added: ${pkg}@${currentDeps[pkg]}`,
          details: { version: currentDeps[pkg] },
        });
      }
    }

    // Removed packages
    for (const pkg of oldPkgs) {
      if (!newPkgs.has(pkg)) {
        events.push({
          type: 'package-removed',
          severity: 'info',
          timestamp: now,
          packageName: pkg,
          message: `Dependency removed: ${pkg}`,
          details: { oldVersion: state.packageVersions[pkg] },
        });
      }
    }

    // Updated packages
    for (const pkg of newPkgs) {
      if (oldPkgs.has(pkg) && currentDeps[pkg] !== state.packageVersions[pkg]) {
        events.push({
          type: 'package-updated',
          severity: 'info',
          timestamp: now,
          packageName: pkg,
          message: `Dependency updated: ${pkg} ${state.packageVersions[pkg]} -> ${currentDeps[pkg]}`,
          details: { oldVersion: state.packageVersions[pkg], newVersion: currentDeps[pkg] },
        });
      }
    }

    state.packageVersions = currentDeps;
  } catch { /* ok */ }

  // 4. Check risk score increases
  if (config.alertOnRiskIncrease) {
    for (const [pkg, score] of Object.entries(currentScores)) {
      const oldScore = state.packageScores[pkg] ?? 0;
      if (score > oldScore && score >= config.riskThreshold) {
        events.push({
          type: 'risk-increased',
          severity: 'critical',
          timestamp: now,
          packageName: pkg,
          message: `Risk score increased for ${pkg}: ${oldScore.toFixed(1)} -> ${score.toFixed(1)}`,
          details: { oldScore, newScore: score, threshold: config.riskThreshold },
        });
      }
    }
    state.packageScores = currentScores;
  }

  // 5. Check for manifest drift
  const manifestPath = join(projectDir, 'shieldpm.json');
  if (existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(await readFile(manifestPath, 'utf-8'));
      const manifestPkgs = new Set(Object.keys(manifest.permissions ?? {}));
      const installedPkgs = new Set(Object.keys(state.packageVersions));

      for (const pkg of installedPkgs) {
        if (!manifestPkgs.has(pkg)) {
          events.push({
            type: 'manifest-drift',
            severity: 'warning',
            timestamp: now,
            packageName: pkg,
            message: `Package "${pkg}" is installed but has no manifest entry`,
            details: {},
          });
        }
      }
    } catch { /* ok */ }
  }

  // Update state
  state.lastCheck = now;
  state.checksPerformed++;
  state.events = [...events, ...state.events].slice(0, config.maxEventsStored);
  await saveState(projectDir, state);

  return events;
}

// ── Status ──────────────────────────────────────────────────────────────

export async function getStatus(projectDir: string): Promise<MonitorStatus> {
  const state = await loadState(projectDir);

  const isConfigured = state.checksPerformed > 0;
  const recentEvents = state.events.slice(0, 10);
  const criticalCount = recentEvents.filter((e) => e.severity === 'critical').length;
  const warningCount = recentEvents.filter((e) => e.severity === 'warning').length;

  let summary = '';
  if (!isConfigured) {
    summary = 'Monitoring not yet initialized. Run: shieldpm monitor check';
  } else if (criticalCount > 0) {
    summary = `${criticalCount} critical alert(s) detected`;
  } else if (warningCount > 0) {
    summary = `${warningCount} warning(s) since last check`;
  } else {
    summary = 'All clear — no issues detected';
  }

  return {
    isConfigured,
    lastCheck: state.lastCheck || null,
    checksPerformed: state.checksPerformed,
    recentEvents,
    lockfileHash: state.lockfileHash || null,
    trackedPackages: Object.keys(state.packageVersions).length,
    summary,
  };
}

export async function clearEvents(projectDir: string): Promise<void> {
  const state = await loadState(projectDir);
  state.events = [];
  await saveState(projectDir, state);
}

export async function initMonitor(projectDir: string): Promise<MonitorState> {
  const state = emptyState();

  state.lockfileHash = await hashFile(join(projectDir, 'package-lock.json'));
  state.packageJsonHash = await hashFile(join(projectDir, 'package.json'));

  try {
    const pkgJson = JSON.parse(await readFile(join(projectDir, 'package.json'), 'utf-8'));
    state.packageVersions = {
      ...(pkgJson.dependencies ?? {}),
      ...(pkgJson.devDependencies ?? {}),
    };
  } catch { /* ok */ }

  state.lastCheck = new Date().toISOString();
  state.checksPerformed = 1;

  await saveState(projectDir, state);
  return state;
}
