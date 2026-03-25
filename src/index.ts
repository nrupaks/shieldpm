/**
 * ShieldPM — Public API
 * Runtime-aware package firewall for Node.js
 *
 * @module shieldpm
 */

// Static analysis
export { analyzePackage, analyzeSource } from './analyzer/static.js';
export type { Finding, RiskReport, Severity } from './analyzer/static.js';

// Typosquatting detection
export { checkTyposquatting, checkMultiple, levenshtein, POPULAR_PACKAGES } from './analyzer/typosquat.js';
export type { TyposquatResult, DetectionMethod } from './analyzer/typosquat.js';

// Sandbox execution
export { runSandboxed, runPostInstall } from './sandbox/runner.js';
export type { SandboxOptions, SandboxResult } from './sandbox/runner.js';

// Permission manifest
export { loadManifest, saveManifest, validateAccess, generateManifest } from './monitor/permissions.js';
export type { PermissionManifest, PackagePermissions, AccessCheck, ResourceType } from './monitor/permissions.js';

// Behavioral fingerprinting
export { generateProfile, diffProfiles, saveProfile, loadProfile } from './fingerprint/profile.js';
export type { BehaviorProfile, ProfileDiff } from './fingerprint/profile.js';

// Dependency diff
export { diffLockfiles, diffLockfilesByPath } from './diff/dependency.js';
export type { DependencyDiffReport, PackageDelta, DeltaFlag } from './diff/dependency.js';

// Utilities
export { log } from './utils/logger.js';
export * as colors from './utils/colors.js';
