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

// Allowlist
export { isAllowlisted, getAllowlistEntry, getAllowlistedNames, applyAllowlist, ALLOWLIST } from './allowlist/index.js';
export type { AllowlistEntry } from './allowlist/index.js';

// SBOM Generation
export { generateSBOM, toCycloneDX, toSPDX, normalizeLicenseId } from './sbom/generator.js';
export type { SBOMDocument, SBOMComponent, SBOMFormat } from './sbom/generator.js';

// License Compliance
export { scanLicenses, detectLicense, classifyLicense, checkCompliance, loadLicensePolicy, generateLicenseReport } from './license/compliance.js';
export type { LicenseInfo, LicensePolicy, LicenseViolation, LicenseReport, LicenseCategory } from './license/compliance.js';

// Policy Engine
export { loadPolicy, savePolicy, initPolicy, evaluatePolicy, buildPolicyContext, DEFAULT_POLICY } from './policy/engine.js';
export type { PolicyDocument, PolicyRule, PolicyContext, PolicyEvaluation, PolicyResult } from './policy/engine.js';

// Package Allow/Deny Lists
export { loadLists, saveLists, addToAllowlist, addToDenylist, removeFromList, checkPackage, checkMultiplePackages, getListStats } from './gateway/lists.js';
export type { PackageLists, PackageListEntry, ListCheckResult } from './gateway/lists.js';

// Compliance Reporting
export { generateComplianceReport, generateAllComplianceReports } from './compliance/reporter.js';
export type { ComplianceReport, ControlMapping, ComplianceFramework, ComplianceInput } from './compliance/reporter.js';

// CI/CD Integration
export { generateGitHubActions, generateGitLabCI, generateAzureDevOps, installPreCommitHook, generatePRComment, evaluateGate, setupCICD, DEFAULT_GATE } from './cicd/integration.js';
export type { GateConfig, GateResult, GateCheck, PRComment, CIProvider } from './cicd/integration.js';

// Provenance Verification
export { verifyProvenance, scanProvenance } from './provenance/verifier.js';
export type { ProvenanceInfo, ProvenanceReport, AttestationInfo, ProvenanceStatus } from './provenance/verifier.js';

// Maintainer Risk Scoring
export { analyzeMaintainer, scanMaintainers } from './maintainer/risk.js';
export type { MaintainerRiskProfile, MaintainerReport, MaintainerRiskLevel } from './maintainer/risk.js';

// Patch Suggestions & Remediation
export { generateSuggestions, generateRemediationReport, getAlternatives } from './remediation/patches.js';
export type { PatchSuggestion, AlternativePackage, RemediationReport, PackageRemediation } from './remediation/patches.js';

// Continuous Monitoring
export { runCheck, getStatus, clearEvents, initMonitor } from './monitoring/watcher.js';
export type { MonitorEvent, MonitorState, MonitorConfig, MonitorStatus } from './monitoring/watcher.js';

// Security Posture Trending
export { createSnapshot, saveSnapshot, loadSnapshots, getLatestSnapshot, analyzeTrend, compareSnapshots } from './posture/trending.js';
export type { PostureSnapshot, PostureMetrics, PostureTrend, PostureComparison, TrendDirection } from './posture/trending.js';

// HTML Report
export { generateHTMLReport, writeHTMLReport } from './report/html.js';
export type { HTMLReportData } from './report/html.js';

// Source Code Scanner
export { scanProject, scanFile } from './scanner/engine.js';
export type { ScanFinding, ScanReport, ScanConfig, ScanSummary } from './scanner/engine.js';

// OWASP Pattern Library
export { ALL_RULES, OWASP_NAMES, getRulesByCategory, getRuleById, getRuleByCWE, getCategoryStats, getTotalRuleCount, getUniqueCWEs } from './scanner/patterns.js';
export type { OWASPRule, OWASPCategory, Confidence } from './scanner/patterns.js';

// OWASP Coverage Report
export { generateOWASPReport, calculateCoverage, buildCWEMatrix, CWE_NAMES } from './scanner/owasp-report.js';
export type { OWASPCoverage, OWASPComplianceReport, CWEEntry } from './scanner/owasp-report.js';

// Utilities
export { log } from './utils/logger.js';
export * as colors from './utils/colors.js';
