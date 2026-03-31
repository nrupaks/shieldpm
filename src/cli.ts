#!/usr/bin/env node
/**
 * ShieldPM — CLI Entry Point
 * Runtime-aware package firewall for Node.js
 *
 * Usage:
 *   shieldpm <command> [options]
 */

import { readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';

import { bold, cyan, red, green, yellow, dim, boldRed, boldGreen, boldYellow, boldCyan, magenta, blue } from './utils/colors.js';
import log from './utils/logger.js';
import { analyzePackage, type RiskReport, type Finding } from './analyzer/static.js';
import { checkTyposquatting, type TyposquatResult } from './analyzer/typosquat.js';
import { runSandboxed, type SandboxResult } from './sandbox/runner.js';
import { loadManifest, saveManifest, generateManifest, validateAccess, type PermissionManifest } from './monitor/permissions.js';
import { generateProfile, diffProfiles, saveProfile, loadProfile } from './fingerprint/profile.js';
import { diffLockfilesByPath, diffLockfiles } from './diff/dependency.js';
import { isAllowlisted, applyAllowlist, getAllowlistEntry } from './allowlist/index.js';

// New modules
import { generateSBOM, toCycloneDX, toSPDX, type SBOMFormat } from './sbom/generator.js';
import { scanLicenses, checkCompliance, loadLicensePolicy, generateLicenseReport } from './license/compliance.js';
import { loadPolicy, savePolicy, initPolicy, evaluatePolicy, buildPolicyContext } from './policy/engine.js';
import { loadLists, saveLists, addToAllowlist, addToDenylist, removeFromList, checkPackage, getListStats } from './gateway/lists.js';
import { generateComplianceReport, generateAllComplianceReports, type ComplianceFramework, type ComplianceInput } from './compliance/reporter.js';
import { setupCICD, installPreCommitHook, evaluateGate, generatePRComment, DEFAULT_GATE, type CIProvider } from './cicd/integration.js';
import { scanProvenance } from './provenance/verifier.js';
import { scanMaintainers } from './maintainer/risk.js';
import { generateRemediationReport } from './remediation/patches.js';
import { runCheck, getStatus, initMonitor } from './monitoring/watcher.js';
import { createSnapshot, saveSnapshot, loadSnapshots, analyzeTrend } from './posture/trending.js';
import { generateHTMLReport, writeHTMLReport, type HTMLReportData } from './report/html.js';
import { scanProject, type ScanConfig, type ScanReport as SourceScanReport } from './scanner/engine.js';
import { generateOWASPReport } from './scanner/owasp-report.js';
import { ALL_RULES, getCategoryStats, OWASP_NAMES, type Severity as ScanSeverity, type Confidence } from './scanner/patterns.js';

// ── Version ──────────────────────────────────────────────────────────────

const VERSION = '0.3.0';

// ── ASCII banner ─────────────────────────────────────────────────────────

function printBanner(): void {
  console.log(boldCyan(`
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ██████╗ ███╗   ███╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔══██╗████╗ ████║
  ███████╗███████║██║█████╗  ██║     ██║  ██║██████╔╝██╔████╔██║
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██╔═══╝ ██║╚██╔╝██║
  ███████║██║  ██║██║███████╗███████╗██████╔╝██║     ██║ ╚═╝ ██║
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚═╝     ╚═╝     ╚═╝
`));
  console.log(dim('  Runtime-aware package firewall for Node.js'));
  console.log();
}

// ── Help text ────────────────────────────────────────────────────────────

function printHelp(): void {
  printBanner();

  console.log(bold('  USAGE'));
  console.log(`    ${cyan('shieldpm')} ${dim('<command>')} ${dim('[options]')}`);
  console.log();

  console.log(bold('  COMMANDS'));
  const commands: [string, string][] = [
    ['install <package>', 'Install a package with protection checks'],
    ['audit', 'Audit current project dependencies'],
    ['audit --deep', 'Deep behavioral analysis of all dependencies'],
    ['inspect <package>', 'Show what a package does (static analysis)'],
    ['sandbox <command>', 'Run a command in a sandboxed environment'],
    ['manifest generate', 'Auto-generate permission manifest'],
    ['manifest enforce', 'Enforce permission manifest at runtime'],
    ['diff', 'Show dependency changes since last lock'],
    ['sbom', 'Generate Software Bill of Materials (CycloneDX/SPDX)'],
    ['license scan', 'Scan all dependency licenses'],
    ['license check', 'Check license compliance against policy'],
    ['policy init', 'Initialize security policy file'],
    ['policy check', 'Evaluate packages against security policy'],
    ['lists show', 'Show allow/deny package lists'],
    ['lists allow <pkg>', 'Add package to allow list'],
    ['lists deny <pkg>', 'Add package to deny list'],
    ['compliance', 'Generate compliance reports (SOC2, ISO, PCI)'],
    ['cicd setup', 'Generate CI/CD workflow (GitHub/GitLab/Azure)'],
    ['hook install', 'Install pre-commit security hook'],
    ['gate', 'Run break-the-build security gate'],
    ['pr-comment', 'Generate PR decoration markdown'],
    ['provenance', 'Verify package provenance & supply chain'],
    ['maintainer', 'Analyze maintainer risk scores'],
    ['remediate', 'Generate patch suggestions & alternatives'],
    ['monitor check', 'Run continuous monitoring check'],
    ['monitor status', 'Show monitoring status'],
    ['posture snapshot', 'Take security posture snapshot'],
    ['posture trend', 'Show posture trend over time'],
    ['report', 'Generate full HTML security report'],
    ['scan', 'Scan project source code for vulnerabilities'],
    ['scan --owasp-report', 'Show OWASP Top 10 coverage report'],
    ['scan --json', 'Output scan results as JSON'],
    ['scan --fix', 'Show inline fix suggestions'],
    ['help', 'Show this help message'],
    ['version', 'Show version'],
  ];

  const maxCmd = Math.max(...commands.map(([c]) => c.length));
  for (const [cmd, desc] of commands) {
    console.log(`    ${green(cmd.padEnd(maxCmd + 2))} ${dim(desc)}`);
  }

  console.log();
  console.log(bold('  OPTIONS'));
  console.log(`    ${green('--verbose')}          ${dim('Enable debug logging')}`);
  console.log(`    ${green('--no-color')}         ${dim('Disable colored output')}`);
  console.log(`    ${green('--json')}             ${dim('Output results as JSON')}`);
  console.log();
  console.log(dim('  https://github.com/nrupaks/shieldpm'));
  console.log();
}

// ── Formatters ───────────────────────────────────────────────────────────

function severityColor(severity: string): (t: string) => string {
  switch (severity) {
    case 'critical': return boldRed;
    case 'high': return red;
    case 'medium': return yellow;
    case 'low': return dim;
    default: return dim;
  }
}

function scoreBar(score: number): string {
  const filled = Math.round(score);
  const empty = 10 - filled;
  const color = score >= 7 ? red : score >= 4 ? yellow : green;
  return color('\u2588'.repeat(filled)) + dim('\u2591'.repeat(empty)) + ` ${score}/10`;
}

function printFindings(findings: Finding[], limit = 20): void {
  const shown = findings.slice(0, limit);
  for (const f of shown) {
    const sev = severityColor(f.severity)(f.severity.toUpperCase().padEnd(8));
    console.log(`  ${sev} ${dim(f.file + ':' + f.line)} ${f.message}`);
    if (f.snippet) {
      console.log(`           ${dim(f.snippet)}`);
    }
  }
  if (findings.length > limit) {
    console.log(dim(`  ... and ${findings.length - limit} more findings`));
  }
}

function printRiskReport(report: RiskReport, packageName?: string): void {
  const label = packageName ? ` for ${bold(packageName)}` : '';
  log.header(`Risk Report${label}`);
  console.log();
  console.log(`  ${bold('Score:')}  ${scoreBar(report.score)}`);
  console.log(`  ${bold('Files:')}  ${report.filesScanned} scanned`);
  console.log(`  ${bold('Result:')} ${report.summary}`);
  console.log();

  if (Object.keys(report.categoryCounts).length > 0) {
    console.log(bold('  Category Breakdown:'));
    for (const [cat, count] of Object.entries(report.categoryCounts)) {
      console.log(`    ${dim(cat.padEnd(24))} ${count} finding${count !== 1 ? 's' : ''}`);
    }
    console.log();
  }

  if (report.findings.length > 0) {
    console.log(bold('  Findings:'));
    printFindings(report.findings);
    console.log();
  }
}

// ── Command handlers ─────────────────────────────────────────────────────

async function cmdInstall(packageName: string, flags: Set<string>): Promise<void> {
  log.header(`Installing ${packageName} with protection`);
  console.log();

  // Step 1: Typosquatting check
  log.info('Checking for typosquatting...');
  const typoResult = checkTyposquatting(packageName);
  if (typoResult) {
    console.log();
    console.log(boldRed('  !! TYPOSQUATTING WARNING !!'));
    console.log(red(`  "${packageName}" looks suspicious:`));
    console.log(yellow(`  Similar to: ${bold(typoResult.similarTo)}`));
    console.log(yellow(`  Method: ${typoResult.method} (distance: ${typoResult.distance})`));
    console.log(yellow(`  ${typoResult.reason}`));
    console.log();
    console.log(red('  Installation blocked. If this is intentional, use --force.'));

    if (!flags.has('--force')) {
      process.exitCode = 1;
      return;
    }
    console.log(yellow('  --force flag set, continuing anyway...'));
    console.log();
  } else {
    log.success('No typosquatting detected');
  }

  // Step 2: Install the package
  log.info(`Running npm install ${packageName}...`);
  try {
    execSync(`npm install --ignore-scripts ${packageName}`, {
      stdio: 'inherit',
      cwd: process.cwd(),
    });
  } catch {
    log.error('npm install failed');
    process.exitCode = 1;
    return;
  }

  // Step 3: Static analysis
  const pkgDir = resolve('node_modules', packageName);
  if (existsSync(pkgDir)) {
    log.info('Running static analysis...');
    const report = await analyzePackage(pkgDir);
    printRiskReport(report, packageName);

    if (report.score >= 7) {
      log.error('Package has critical risk score. Review findings above.');
      console.log(yellow('  To keep the package, add it to your shieldpm.json manifest.'));
    } else if (report.score >= 4) {
      log.warn('Package has elevated risk. Review findings above.');
    } else {
      log.success('Package appears safe.');
    }

    // Step 4: Generate profile
    try {
      const pkgJson = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf-8'));
      const profile = await generateProfile(pkgDir, packageName, pkgJson.version ?? '0.0.0');
      const profilePath = await saveProfile(process.cwd(), profile);
      log.info(`Behavioral profile saved: ${dim(profilePath)}`);
    } catch {
      log.warn('Could not generate behavioral profile');
    }

    // Step 5: Run postinstall in sandbox if present
    try {
      const pkgJson = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf-8'));
      const postinstall = pkgJson.scripts?.postinstall || pkgJson.scripts?.install;
      if (postinstall) {
        log.info('Running postinstall script in sandbox...');
        const result = await runSandboxed('sh', ['-c', postinstall], {
          cwd: pkgDir,
          timeout: 30_000,
          blockNetwork: true,
          blockEnv: true,
        });

        if (result.warnings.length > 0) {
          for (const w of result.warnings) log.warn(w);
        }
        if (result.blocked.length > 0) {
          for (const b of result.blocked) log.info(`Blocked: ${b}`);
        }
        if (result.exitCode === 0) {
          log.success('Postinstall completed in sandbox');
        } else {
          log.warn(`Postinstall exited with code ${result.exitCode}`);
        }
      }
    } catch {
      // No postinstall — fine
    }
  }

  console.log();
}

async function cmdAudit(deep: boolean, flags: Set<string>): Promise<void> {
  log.header(deep ? 'Deep Dependency Audit' : 'Dependency Audit');
  console.log();

  const nodeModules = resolve('node_modules');
  if (!existsSync(nodeModules)) {
    log.error('No node_modules found. Run npm install first.');
    process.exitCode = 1;
    return;
  }

  // Read top-level dependencies from package.json
  let deps: string[] = [];
  try {
    const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
    deps = [
      ...Object.keys(pkgJson.dependencies ?? {}),
      ...Object.keys(pkgJson.devDependencies ?? {}),
    ];
  } catch {
    log.error('Cannot read package.json');
    process.exitCode = 1;
    return;
  }

  if (deps.length === 0) {
    log.info('No dependencies found.');
    return;
  }

  log.info(`Scanning ${deps.length} dependencies...`);
  console.log();

  let totalScore = 0;
  let maxScore = 0;
  let maxPkg = '';
  const highRisk: { name: string; score: number }[] = [];

  for (const dep of deps) {
    const pkgDir = resolve('node_modules', dep);
    if (!existsSync(pkgDir)) {
      log.warn(`${dep}: not found in node_modules`);
      continue;
    }

    const report = await analyzePackage(pkgDir);

    // Apply allowlist
    const { adjustedScore, suppressed, entry: allowEntry } = applyAllowlist(dep, report.score, report.findings);
    const displayScore = adjustedScore;
    totalScore += displayScore;

    if (displayScore > maxScore) {
      maxScore = displayScore;
      maxPkg = dep;
    }

    const scoreStr = displayScore >= 7
      ? boldRed(displayScore.toFixed(1))
      : displayScore >= 4
        ? boldYellow(displayScore.toFixed(1))
        : boldGreen(displayScore.toFixed(1));

    const allowTag = suppressed ? dim(' [allowlisted]') : '';
    console.log(`  ${scoreStr.padStart(18)} ${dep} ${dim(`(${report.findings.length} findings)`)}${allowTag}`);

    if (displayScore >= 4) {
      highRisk.push({ name: dep, score: displayScore });
    }

    if (deep && report.findings.length > 0) {
      printFindings(report.findings, 5);
      console.log();
    }

    // Typosquatting check
    const typo = checkTyposquatting(dep);
    if (typo) {
      console.log(yellow(`           Typosquatting alert: similar to "${typo.similarTo}" (${typo.method})`));
    }
  }

  console.log();
  console.log(bold('  Summary:'));
  console.log(`    Packages scanned:  ${deps.length}`);
  console.log(`    Average risk score: ${(totalScore / deps.length).toFixed(1)}/10`);
  console.log(`    Highest risk:      ${maxPkg} (${maxScore.toFixed(1)}/10)`);

  if (highRisk.length > 0) {
    console.log();
    console.log(boldYellow(`  ${highRisk.length} package(s) need attention:`));
    for (const pkg of highRisk) {
      console.log(yellow(`    - ${pkg.name} (${pkg.score.toFixed(1)}/10)`));
    }
  }

  console.log();

  if (flags.has('--json')) {
    // Could output machine-readable results; for now just note it
    log.info('JSON output: use --json with programmatic API for structured data');
  }
}

async function cmdInspect(packageName: string): Promise<void> {
  // Try node_modules first, then treat as a directory
  let targetDir = resolve('node_modules', packageName);
  if (!existsSync(targetDir)) {
    targetDir = resolve(packageName);
  }
  if (!existsSync(targetDir)) {
    log.error(`Package "${packageName}" not found in node_modules or as a path.`);
    log.info('Install it first: shieldpm install ' + packageName);
    process.exitCode = 1;
    return;
  }

  const report = await analyzePackage(targetDir);
  printRiskReport(report, packageName);

  // Also show imports and profile
  try {
    const pkgJson = JSON.parse(await readFile(join(targetDir, 'package.json'), 'utf-8'));
    const version = pkgJson.version ?? 'unknown';
    const profile = await generateProfile(targetDir, packageName, version);

    if (profile.imports.length > 0) {
      console.log(bold('  Imports:'));
      for (const imp of profile.imports.slice(0, 30)) {
        const isBuiltin = !imp.startsWith('.') && !imp.startsWith('/');
        console.log(`    ${isBuiltin ? cyan(imp) : dim(imp)}`);
      }
      if (profile.imports.length > 30) {
        console.log(dim(`    ... and ${profile.imports.length - 30} more`));
      }
      console.log();
    }

    if (profile.networkEndpoints.length > 0) {
      console.log(boldYellow('  Network Endpoints:'));
      for (const ep of profile.networkEndpoints) {
        console.log(`    ${yellow(ep)}`);
      }
      console.log();
    }

    if (profile.nativeBindings.length > 0) {
      console.log(bold('  Native Bindings:'));
      for (const nb of profile.nativeBindings) {
        console.log(`    ${red(nb)}`);
      }
      console.log();
    }
  } catch {
    // Not a valid package directory
  }
}

async function cmdSandbox(command: string[]): Promise<void> {
  if (command.length === 0) {
    log.error('No command specified. Usage: shieldpm sandbox <command>');
    process.exitCode = 1;
    return;
  }

  const fullCommand = command.join(' ');
  log.header(`Sandboxing: ${fullCommand}`);
  console.log();

  log.info('Environment: network blocked, env stripped, 30s timeout');
  console.log();

  const result = await runSandboxed(command[0], command.slice(1), {
    timeout: 30_000,
    blockNetwork: true,
    blockEnv: true,
  });

  if (result.stdout) {
    console.log(dim('  --- stdout ---'));
    console.log(result.stdout);
  }
  if (result.stderr) {
    console.log(dim('  --- stderr ---'));
    console.log(result.stderr);
  }

  console.log();

  if (result.blocked.length > 0) {
    console.log(bold('  Blocked:'));
    for (const b of result.blocked) {
      console.log(`    ${red(b)}`);
    }
  }

  if (result.warnings.length > 0) {
    console.log(bold('  Warnings:'));
    for (const w of result.warnings) {
      console.log(`    ${yellow(w)}`);
    }
  }

  console.log();
  console.log(`  Exit code: ${result.exitCode ?? 'killed'}`);
  console.log(`  Duration:  ${result.durationMs}ms`);
  if (result.timedOut) {
    console.log(boldRed('  TIMED OUT'));
  }
  console.log();

  process.exitCode = result.exitCode ?? 1;
}

async function cmdManifestGenerate(): Promise<void> {
  log.header('Generating Permission Manifest');
  console.log();

  const projectDir = process.cwd();
  log.info('Scanning dependencies...');

  const manifest = await generateManifest(projectDir);
  const pkgCount = Object.keys(manifest.permissions).length;

  if (pkgCount === 0) {
    log.warn('No packages found in node_modules.');
    return;
  }

  const path = await saveManifest(manifest, projectDir);
  log.success(`Generated manifest for ${pkgCount} packages`);
  log.info(`Saved to: ${dim(path)}`);
  console.log();
  console.log(dim('  Review the manifest and fill in allowed destinations/paths.'));
  console.log(dim('  Then run: shieldpm manifest enforce'));
  console.log();
}

async function cmdManifestEnforce(): Promise<void> {
  log.header('Enforcing Permission Manifest');
  console.log();

  const manifest = await loadManifest();
  if (!manifest) {
    log.error('No shieldpm.json found. Run: shieldpm manifest generate');
    process.exitCode = 1;
    return;
  }

  const pkgCount = Object.keys(manifest.permissions).length;
  log.info(`Loaded manifest with ${pkgCount} package rules`);
  console.log();

  // Validate that all installed deps have manifest entries
  try {
    const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
    const deps = [
      ...Object.keys(pkgJson.dependencies ?? {}),
      ...Object.keys(pkgJson.devDependencies ?? {}),
    ];

    let missing = 0;
    let covered = 0;

    for (const dep of deps) {
      if (manifest.permissions[dep]) {
        covered++;
        const perms = manifest.permissions[dep];
        const restrictions: string[] = [];
        if (perms.net === false) restrictions.push('net:blocked');
        else if (Array.isArray(perms.net)) restrictions.push(`net:${perms.net.length} rules`);
        if (perms.fs === false) restrictions.push('fs:blocked');
        else if (Array.isArray(perms.fs)) restrictions.push(`fs:${perms.fs.length} paths`);
        if (perms.native) restrictions.push('native:yes');
        if (perms.exec) restrictions.push('exec:yes');

        console.log(`  ${green('\u2713')} ${dep} ${dim(`[${restrictions.join(', ')}]`)}`);
      } else {
        missing++;
        console.log(`  ${red('\u2717')} ${dep} ${red('(no manifest entry — will be fully restricted)')}`);
      }
    }

    console.log();
    console.log(`  Covered: ${covered}/${deps.length}`);
    if (missing > 0) {
      log.warn(`${missing} packages have no manifest entry and will be fully restricted.`);
      log.info('Run: shieldpm manifest generate');
    } else {
      log.success('All dependencies have manifest entries.');
    }
  } catch {
    log.error('Cannot read package.json');
    process.exitCode = 1;
  }

  console.log();
}

async function cmdDiff(): Promise<void> {
  log.header('Dependency Diff');
  console.log();

  // Look for git-tracked package-lock.json
  const lockPath = resolve('package-lock.json');
  if (!existsSync(lockPath)) {
    log.error('No package-lock.json found.');
    process.exitCode = 1;
    return;
  }

  // Get the last committed version
  let oldLock: string;
  try {
    oldLock = execSync('git show HEAD:package-lock.json', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    log.error('Could not get previous package-lock.json from git.');
    log.info('This command requires a git repository with a committed package-lock.json.');
    process.exitCode = 1;
    return;
  }

  const newLock = await readFile(lockPath, 'utf-8');
  const report = diffLockfiles(oldLock, newLock);

  console.log(`  ${dim('Old packages:')} ${report.oldPackageCount}`);
  console.log(`  ${dim('New packages:')} ${report.newPackageCount}`);
  console.log();

  if (report.added.length > 0) {
    console.log(bold(green(`  + ${report.added.length} added:`)));
    for (const pkg of report.added) {
      console.log(`    ${green('+')} ${pkg.name} ${dim(pkg.newVersion ?? '')}`);
      for (const flag of pkg.flags) {
        console.log(`      ${yellow('!')} ${flag.message}`);
      }
    }
    console.log();
  }

  if (report.removed.length > 0) {
    console.log(bold(red(`  - ${report.removed.length} removed:`)));
    for (const pkg of report.removed) {
      console.log(`    ${red('-')} ${pkg.name} ${dim(pkg.oldVersion ?? '')}`);
    }
    console.log();
  }

  if (report.changed.length > 0) {
    console.log(bold(yellow(`  ~ ${report.changed.length} changed:`)));
    for (const pkg of report.changed) {
      console.log(`    ${yellow('~')} ${pkg.name} ${dim((pkg.oldVersion ?? '') + ' -> ' + (pkg.newVersion ?? ''))}`);
      for (const flag of pkg.flags) {
        console.log(`      ${yellow('!')} ${flag.message}`);
      }
    }
    console.log();
  }

  if (report.flags.length > 0) {
    console.log(boldYellow(`  ${report.flags.length} flag(s) to review`));
  } else if (report.added.length === 0 && report.removed.length === 0 && report.changed.length === 0) {
    log.success('No dependency changes detected.');
  }

  console.log();
}

// ── New Command Handlers ────────────────────────────────────────────────

async function cmdSBOM(flags: Set<string>): Promise<void> {
  log.header('Generating SBOM');
  console.log();

  const format: SBOMFormat = flags.has('--format=spdx') ? 'spdx' : 'cyclonedx';
  const doc = await generateSBOM(process.cwd(), format);

  console.log(`  ${bold('Format:')}    ${format === 'cyclonedx' ? 'CycloneDX 1.5' : 'SPDX 2.3'}`);
  console.log(`  ${bold('Project:')}   ${doc.subject.name}@${doc.subject.version}`);
  console.log(`  ${bold('Components:')} ${doc.totalComponents}`);
  console.log();

  const output = format === 'cyclonedx' ? toCycloneDX(doc) : toSPDX(doc);

  // Find --output flag
  let outputPath = '';
  for (const f of flags) {
    if (f.startsWith('--output=')) outputPath = f.slice(9);
  }

  if (outputPath || flags.has('--json')) {
    const path = outputPath || `sbom-${format}.json`;
    const { writeFile } = await import('node:fs/promises');
    await writeFile(path, JSON.stringify(output, null, 2) + '\n', 'utf-8');
    log.success(`SBOM written to ${path}`);
  } else {
    console.log(JSON.stringify(output, null, 2));
  }
  console.log();
}

async function cmdLicense(subcommand: string): Promise<void> {
  log.header(subcommand === 'check' ? 'License Compliance Check' : 'License Scan');
  console.log();

  const licenses = await scanLicenses(process.cwd());

  if (licenses.length === 0) {
    log.info('No packages found.');
    return;
  }

  if (subcommand === 'check') {
    const policy = loadLicensePolicy();
    const violations = checkCompliance(licenses, policy);
    const report = generateLicenseReport(licenses, violations);

    console.log(bold('  License Distribution:'));
    console.log(`    Permissive:     ${green(String(report.summary.permissive))}`);
    console.log(`    Weak Copyleft:  ${yellow(String(report.summary.weakCopyleft))}`);
    console.log(`    Copyleft:       ${red(String(report.summary.copyleft))}`);
    console.log(`    Unknown:        ${dim(String(report.summary.unknown))}`);
    console.log();

    if (violations.length > 0) {
      console.log(boldRed(`  ${violations.length} Violation(s):`));
      for (const v of violations) {
        console.log(`    ${red('x')} ${v.packageName}: ${v.message}`);
      }
      process.exitCode = 1;
    } else {
      log.success('All licenses comply with policy.');
    }
  } else {
    for (const lic of licenses) {
      const catColor = lic.category === 'permissive' ? green
        : lic.category === 'copyleft' ? red
          : lic.category === 'weak-copyleft' ? yellow : dim;
      console.log(`  ${catColor(lic.category.padEnd(14))} ${dim(lic.license.padEnd(18))} ${lic.packageName}`);
    }
    console.log();
    console.log(`  Total: ${licenses.length} packages`);
  }
  console.log();
}

async function cmdPolicy(subcommand: string): Promise<void> {
  if (subcommand === 'init') {
    log.header('Initializing Security Policy');
    console.log();
    const path = await initPolicy();
    log.success(`Policy file created: ${dim(path)}`);
    console.log(dim('  Edit shieldpm-policy.json to customize rules.'));
    console.log();
    return;
  }

  log.header('Policy Evaluation');
  console.log();

  const policy = await loadPolicy();
  log.info(`Loaded policy: ${bold(policy.name)} (${policy.rules.filter(r => r.enabled).length} active rules)`);
  console.log();

  const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
  const deps = Object.keys(pkgJson.dependencies ?? {});
  let blocked = 0;
  let warnings = 0;

  for (const dep of deps) {
    const pkgDir = resolve('node_modules', dep);
    if (!existsSync(pkgDir)) continue;

    const report = await analyzePackage(pkgDir);
    const ctx = buildPolicyContext(dep, {
      version: '0.0.0',
      riskScore: report.score,
      findingCount: report.findings.length,
      criticalFindings: report.findings.filter(f => f.severity === 'critical').length,
      highFindings: report.findings.filter(f => f.severity === 'high').length,
      hasInstallScripts: report.categoryCounts['install-script'] > 0,
    });

    const result = evaluatePolicy(policy, ctx);

    if (result.blocked) {
      blocked++;
      console.log(`  ${boldRed('BLOCKED')} ${dep}`);
      for (const r of result.results.filter(r => !r.passed)) {
        console.log(`    ${red('x')} ${r.message}`);
      }
    } else if (result.warnings > 0) {
      warnings++;
      console.log(`  ${boldYellow('WARN')}    ${dep}`);
      for (const r of result.results.filter(r => !r.passed)) {
        console.log(`    ${yellow('!')} ${r.message}`);
      }
    } else {
      console.log(`  ${boldGreen('PASS')}    ${dep}`);
    }
  }

  console.log();
  console.log(`  ${bold('Results:')} ${deps.length} packages, ${blocked} blocked, ${warnings} warnings`);
  if (blocked > 0) process.exitCode = 1;
  console.log();
}

async function cmdLists(subcommand: string, args: string[]): Promise<void> {
  const lists = await loadLists();

  if (subcommand === 'show') {
    log.header('Package Lists');
    console.log();
    const stats = getListStats(lists);

    if (lists.allowlist.length > 0) {
      console.log(bold(green('  Allowlist:')));
      for (const e of lists.allowlist) {
        console.log(`    ${green('+')} ${e.name} — ${dim(e.reason)}`);
      }
      console.log();
    }
    if (lists.denylist.length > 0) {
      console.log(bold(red('  Denylist:')));
      for (const e of lists.denylist) {
        console.log(`    ${red('-')} ${e.name} — ${dim(e.reason)}`);
      }
      console.log();
    }
    if (lists.allowlist.length === 0 && lists.denylist.length === 0) {
      log.info('No packages in allow/deny lists.');
    }
    console.log();
    return;
  }

  const pkgName = args[0];
  if (!pkgName) {
    log.error('Missing package name.');
    process.exitCode = 1;
    return;
  }

  const reason = args.slice(1).join(' ') || 'Added via CLI';

  if (subcommand === 'allow') {
    addToAllowlist(lists, pkgName, reason);
    await saveLists(lists);
    log.success(`Added "${pkgName}" to allowlist`);
  } else if (subcommand === 'deny') {
    addToDenylist(lists, pkgName, reason);
    await saveLists(lists);
    log.success(`Added "${pkgName}" to denylist`);
  } else if (subcommand === 'remove') {
    removeFromList(lists, pkgName);
    await saveLists(lists);
    log.success(`Removed "${pkgName}" from all lists`);
  }
  console.log();
}

async function cmdCompliance(flags: Set<string>): Promise<void> {
  log.header('Compliance Report');
  console.log();

  const nodeModules = resolve('node_modules');
  const riskReports = new Map<string, RiskReport>();

  const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
  const deps = [...Object.keys(pkgJson.dependencies ?? {}), ...Object.keys(pkgJson.devDependencies ?? {})];

  for (const dep of deps) {
    const pkgDir = resolve('node_modules', dep);
    if (existsSync(pkgDir)) {
      riskReports.set(dep, await analyzePackage(pkgDir));
    }
  }

  const input: ComplianceInput = {
    riskReports,
    hasManifest: existsSync(resolve('shieldpm.json')),
    hasLockfile: existsSync(resolve('package-lock.json')),
    hasSBOM: false,
    hasPolicy: existsSync(resolve('shieldpm-policy.json')),
  };

  const reports = generateAllComplianceReports(input, pkgJson.name ?? 'unknown');

  for (const report of reports) {
    console.log(`  ${bold(report.frameworkName)}: ${report.summary.complianceScore}% compliant`);
    console.log(`    ${green('Met:')} ${report.summary.met}  ${yellow('Partial:')} ${report.summary.partial}  ${red('Not Met:')} ${report.summary.notMet}`);

    for (const ctrl of report.controls) {
      const icon = ctrl.status === 'met' ? green('\u2713') : ctrl.status === 'partial' ? yellow('~') : red('\u2717');
      console.log(`    ${icon} ${ctrl.controlId} ${dim(ctrl.controlName)}`);
    }
    console.log();
  }
}

async function cmdCICD(args: string[]): Promise<void> {
  const provider = (args[0] ?? 'github-actions') as CIProvider;
  log.header(`CI/CD Setup: ${provider}`);
  console.log();

  const path = await setupCICD(process.cwd(), provider);
  log.success(`Workflow created: ${dim(path)}`);
  console.log(dim('  Commit this file to enable automated security scans.'));
  console.log();
}

async function cmdHookInstall(): Promise<void> {
  log.header('Installing Pre-Commit Hook');
  console.log();

  const path = await installPreCommitHook(process.cwd());
  log.success(`Hook installed: ${dim(path)}`);
  console.log(dim('  Dependency changes will be scanned before each commit.'));
  console.log();
}

async function cmdGate(flags: Set<string>): Promise<void> {
  log.header('Security Gate');
  console.log();

  const riskReports = new Map<string, RiskReport>();
  const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
  const deps = [...Object.keys(pkgJson.dependencies ?? {}), ...Object.keys(pkgJson.devDependencies ?? {})];

  for (const dep of deps) {
    const pkgDir = resolve('node_modules', dep);
    if (existsSync(pkgDir)) {
      riskReports.set(dep, await analyzePackage(pkgDir));
    }
  }

  const gate = { ...DEFAULT_GATE };
  for (const f of flags) {
    if (f.startsWith('--max-risk-score=')) gate.maxRiskScore = parseInt(f.split('=')[1]);
    if (f.startsWith('--max-critical=')) gate.maxCriticalFindings = parseInt(f.split('=')[1]);
    if (f.startsWith('--max-high=')) gate.maxHighFindings = parseInt(f.split('=')[1]);
  }

  const result = evaluateGate(riskReports, gate);

  for (const check of result.checks) {
    const icon = check.passed ? boldGreen('\u2713') : boldRed('\u2717');
    console.log(`  ${icon} ${check.name}: ${check.message}`);
  }

  console.log();
  if (result.passed) {
    log.success(result.summary);
  } else {
    log.error(result.summary);
    process.exitCode = result.exitCode;
  }
  console.log();
}

async function cmdPRComment(): Promise<void> {
  const riskReports = new Map<string, RiskReport>();
  const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
  const deps = [...Object.keys(pkgJson.dependencies ?? {}), ...Object.keys(pkgJson.devDependencies ?? {})];

  for (const dep of deps) {
    const pkgDir = resolve('node_modules', dep);
    if (existsSync(pkgDir)) {
      riskReports.set(dep, await analyzePackage(pkgDir));
    }
  }

  const comment = generatePRComment(riskReports);
  console.log(comment.body);
}

async function cmdProvenance(): Promise<void> {
  log.header('Package Provenance');
  console.log();

  const report = await scanProvenance(process.cwd());

  for (const pkg of report.packages) {
    const icon = pkg.status === 'verified' ? green('\u2713')
      : pkg.status === 'unverified' ? yellow('~')
        : red('\u2717');
    const statusLabel = pkg.status === 'verified' ? boldGreen('VERIFIED')
      : pkg.status === 'unverified' ? boldYellow('UNVERIFIED')
        : dim('MISSING');

    console.log(`  ${icon} ${statusLabel.padEnd(24)} ${pkg.packageName}`);
    if (pkg.sourceRepo) console.log(`    ${dim('repo:')} ${dim(pkg.sourceRepo)}`);
    for (const rf of pkg.riskFactors) {
      console.log(`    ${yellow('!')} ${rf}`);
    }
  }

  console.log();
  console.log(`  ${bold('Coverage:')} ${report.summary.provenanceCoverage}% (${report.summary.verified}/${report.summary.total} verified)`);
  console.log();
}

async function cmdMaintainer(): Promise<void> {
  log.header('Maintainer Risk Analysis');
  console.log();

  const report = await scanMaintainers(process.cwd());

  for (const pkg of report.packages.slice(0, 30)) {
    const levelColor = pkg.riskLevel === 'critical' ? boldRed
      : pkg.riskLevel === 'high' ? red
        : pkg.riskLevel === 'medium' ? yellow : green;

    console.log(`  ${levelColor(pkg.riskLevel.toUpperCase().padEnd(8))} ${pkg.packageName} ${dim(`(${pkg.maintainerCount} maintainer${pkg.maintainerCount !== 1 ? 's' : ''})`)}`);
    for (const rf of pkg.riskFactors) {
      console.log(`    ${dim(rf.factor + ':')} ${rf.description}`);
    }
  }

  console.log();
  console.log(bold('  Summary:'));
  console.log(`    Low: ${report.summary.low}  Medium: ${report.summary.medium}  High: ${report.summary.high}  Critical: ${report.summary.critical}`);
  console.log(`    Single-maintainer packages: ${report.summary.singleMaintainerCount}/${report.summary.total}`);
  console.log();
}

async function cmdRemediate(): Promise<void> {
  log.header('Remediation Suggestions');
  console.log();

  const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
  const deps = [...Object.keys(pkgJson.dependencies ?? {}), ...Object.keys(pkgJson.devDependencies ?? {})];
  const packages: Array<{ name: string; version: string; report: RiskReport }> = [];

  for (const dep of deps) {
    const pkgDir = resolve('node_modules', dep);
    if (!existsSync(pkgDir)) continue;
    const report = await analyzePackage(pkgDir);
    let version = '0.0.0';
    try {
      const dpkg = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf-8'));
      version = dpkg.version ?? '0.0.0';
    } catch {}
    packages.push({ name: dep, version, report });
  }

  const remReport = generateRemediationReport(packages);

  if (remReport.packages.length === 0) {
    log.success('No remediation needed — all packages look clean.');
    return;
  }

  for (const pkg of remReport.packages) {
    console.log(`  ${bold(pkg.packageName)} ${dim(`(${pkg.riskScore.toFixed(1)}/10)`)}`);
    for (const s of pkg.suggestions.slice(0, 3)) {
      const prioColor = s.priority === 'critical' ? red : s.priority === 'high' ? yellow : dim;
      console.log(`    ${prioColor(s.priority.toUpperCase().padEnd(8))} ${s.title}`);
      console.log(`    ${dim(s.action)}`);
    }
    console.log();
  }

  console.log(bold('  Summary:'));
  console.log(`    ${remReport.summary.total} suggestions (${remReport.summary.critical} critical, ${remReport.summary.high} high)`);
  console.log(`    Estimated effort: ${remReport.summary.estimatedEffort}`);
  console.log();
}

async function cmdMonitor(subcommand: string): Promise<void> {
  if (subcommand === 'init') {
    log.header('Initializing Monitor');
    console.log();
    await initMonitor(process.cwd());
    log.success('Monitor initialized. Run "shieldpm monitor check" to scan for changes.');
    console.log();
    return;
  }

  if (subcommand === 'status') {
    log.header('Monitor Status');
    console.log();
    const status = await getStatus(process.cwd());
    console.log(`  Configured:  ${status.isConfigured ? green('Yes') : red('No')}`);
    console.log(`  Last check:  ${status.lastCheck ?? dim('never')}`);
    console.log(`  Checks run:  ${status.checksPerformed}`);
    console.log(`  Tracked:     ${status.trackedPackages} packages`);
    console.log(`  Status:      ${status.summary}`);

    if (status.recentEvents.length > 0) {
      console.log();
      console.log(bold('  Recent Events:'));
      for (const e of status.recentEvents.slice(0, 5)) {
        const sevColor = e.severity === 'critical' ? red : e.severity === 'warning' ? yellow : dim;
        console.log(`    ${sevColor(e.severity.padEnd(8))} ${e.message}`);
      }
    }
    console.log();
    return;
  }

  // Default: check
  log.header('Monitor Check');
  console.log();

  const events = await runCheck(process.cwd());

  if (events.length === 0) {
    log.success('No changes detected since last check.');
  } else {
    for (const e of events) {
      const sevColor = e.severity === 'critical' ? boldRed : e.severity === 'warning' ? boldYellow : dim;
      console.log(`  ${sevColor(e.severity.toUpperCase().padEnd(8))} ${e.message}`);
    }
    console.log();
    console.log(`  ${events.length} event(s) detected`);
  }
  console.log();
}

async function cmdPosture(subcommand: string): Promise<void> {
  if (subcommand === 'snapshot') {
    log.header('Security Posture Snapshot');
    console.log();

    const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
    const deps = [...Object.keys(pkgJson.dependencies ?? {}), ...Object.keys(pkgJson.devDependencies ?? {})];
    const scores: Record<string, number> = {};
    let totalFindings = 0;
    let criticalFindings = 0;
    let highFindings = 0;

    for (const dep of deps) {
      const pkgDir = resolve('node_modules', dep);
      if (!existsSync(pkgDir)) continue;
      const report = await analyzePackage(pkgDir);
      const { adjustedScore } = applyAllowlist(dep, report.score, report.findings);
      scores[dep] = adjustedScore;
      totalFindings += report.findings.length;
      criticalFindings += report.findings.filter(f => f.severity === 'critical').length;
      highFindings += report.findings.filter(f => f.severity === 'high').length;
    }

    const snapshot = createSnapshot(pkgJson.name ?? 'unknown', scores, {
      totalFindings, criticalFindings, highFindings,
      manifestCoverage: existsSync(resolve('shieldpm.json')) ? 100 : 0,
    });

    const path = await saveSnapshot(process.cwd(), snapshot);
    log.success(`Snapshot saved: ${dim(path)}`);
    console.log(`  Score: ${bold(String(snapshot.metrics.overallScore))}/100`);
    console.log(`  Packages: ${snapshot.packageCount}`);
    console.log(`  High risk: ${snapshot.highRiskPackages.length}`);
    console.log();
    return;
  }

  // Trend
  log.header('Security Posture Trend');
  console.log();

  const snapshots = await loadSnapshots(process.cwd());

  if (snapshots.length === 0) {
    log.info('No snapshots found. Run: shieldpm posture snapshot');
    console.log();
    return;
  }

  const trend = analyzeTrend(snapshots);
  const trendColor = trend.trend === 'improving' ? green : trend.trend === 'declining' ? red : yellow;

  console.log(`  Trend:    ${trendColor(trend.trend.toUpperCase())} (${trend.changePercent >= 0 ? '+' : ''}${trend.changePercent}%)`);
  console.log(`  Period:   ${trend.periodStart.slice(0, 10)} to ${trend.periodEnd.slice(0, 10)}`);
  console.log(`  Snapshots: ${trend.snapshots.length}`);
  console.log();

  if (trend.improvements.length > 0) {
    console.log(green('  Improvements:'));
    for (const i of trend.improvements) console.log(`    ${green('\u2713')} ${i}`);
    console.log();
  }
  if (trend.regressions.length > 0) {
    console.log(red('  Regressions:'));
    for (const r of trend.regressions) console.log(`    ${red('\u2717')} ${r}`);
    console.log();
  }
}

async function cmdReport(flags: Set<string>): Promise<void> {
  log.header('Generating HTML Report');
  console.log();

  const pkgJson = JSON.parse(await readFile(resolve('package.json'), 'utf-8'));
  const deps = [...Object.keys(pkgJson.dependencies ?? {}), ...Object.keys(pkgJson.devDependencies ?? {})];

  log.info(`Scanning ${deps.length} packages...`);

  // Collect all data
  const riskReports = new Map<string, RiskReport>();
  const packages: Array<{ name: string; version: string; report: RiskReport }> = [];

  for (const dep of deps) {
    const pkgDir = resolve('node_modules', dep);
    if (!existsSync(pkgDir)) continue;
    const report = await analyzePackage(pkgDir);
    riskReports.set(dep, report);
    let version = '0.0.0';
    try { version = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf-8')).version ?? '0.0.0'; } catch {}
    packages.push({ name: dep, version, report });
  }

  log.info('Generating SBOM...');
  const sbom = await generateSBOM(process.cwd());

  log.info('Scanning licenses...');
  const licenses = await scanLicenses(process.cwd());
  const licPolicy = loadLicensePolicy();
  const licViolations = checkCompliance(licenses, licPolicy);
  const licenseReport = generateLicenseReport(licenses, licViolations);

  log.info('Running compliance checks...');
  const complianceInput: ComplianceInput = {
    riskReports,
    licenseReport,
    sbom,
    hasManifest: existsSync(resolve('shieldpm.json')),
    hasLockfile: existsSync(resolve('package-lock.json')),
    hasSBOM: true,
    hasPolicy: existsSync(resolve('shieldpm-policy.json')),
  };
  const complianceReports = generateAllComplianceReports(complianceInput, pkgJson.name);

  log.info('Analyzing provenance...');
  const provenanceReport = await scanProvenance(process.cwd());

  log.info('Analyzing maintainers...');
  const maintainerReport = await scanMaintainers(process.cwd());

  log.info('Generating remediation suggestions...');
  const remediationReport = generateRemediationReport(packages);

  log.info('Loading posture trend...');
  const snapshots = await loadSnapshots(process.cwd());
  const postureTrend = analyzeTrend(snapshots);

  log.info('Loading monitor status...');
  const monitorStatus = await getStatus(process.cwd());

  const gate = evaluateGate(riskReports);

  const reportData: HTMLReportData = {
    projectName: pkgJson.name ?? 'unknown',
    version: pkgJson.version ?? '0.0.0',
    generatedAt: new Date().toISOString(),
    riskReports,
    sbom,
    licenseReport,
    complianceReports,
    provenanceReport,
    maintainerReport,
    remediationReport,
    postureTrend,
    monitorStatus,
    gateResult: gate,
  };

  let outputPath = 'shieldpm-report.html';
  for (const f of flags) {
    if (f.startsWith('--output=')) outputPath = f.slice(9);
  }

  await writeHTMLReport(outputPath, reportData);
  log.success(`Report generated: ${bold(outputPath)}`);
  console.log(dim('  Open in a browser to view the interactive report.'));
  console.log();
}

async function cmdScan(flags: Set<string>): Promise<void> {
  // Parse flags
  let dir = '.';
  let severityThreshold: ScanSeverity = 'low';
  let confidenceThreshold: Confidence = 'low';

  for (const f of flags) {
    if (f.startsWith('--dir=')) dir = f.slice(6);
    if (f.startsWith('--severity=')) severityThreshold = f.slice(11) as ScanSeverity;
    if (f.startsWith('--confidence=')) confidenceThreshold = f.slice(13) as Confidence;
  }

  // OWASP report mode
  if (flags.has('--owasp-report')) {
    log.header('OWASP Top 10 Coverage Report');
    console.log();

    // Run scan first if dir exists
    let scanReport: SourceScanReport | undefined;
    try {
      scanReport = await scanProject({ dir, severityThreshold, confidenceThreshold });
    } catch { /* ok — show coverage without scan */ }

    const owaspReport = generateOWASPReport(scanReport);

    console.log(`  ${bold('Total Rules:')}  ${owaspReport.totalRules}`);
    console.log(`  ${bold('Unique CWEs:')} ${owaspReport.totalCWEs}`);
    console.log(`  ${bold('Score:')}       ${owaspReport.overallScore}/100 (${owaspReport.overallLevel})`);
    console.log();

    console.log(bold('  OWASP Top 10 Coverage:'));
    for (const cat of owaspReport.categories) {
      if (cat.category === 'EXTRA') continue;
      const levelColor = cat.coverageLevel === 'comprehensive' ? boldGreen
        : cat.coverageLevel === 'good' ? green
          : cat.coverageLevel === 'basic' ? yellow
            : cat.coverageLevel === 'minimal' ? red : dim;
      const findingCount = owaspReport.scanResults?.findingsByCategory[cat.category] ?? 0;
      const findingSuffix = scanReport ? ` | ${findingCount} finding${findingCount !== 1 ? 's' : ''}` : '';
      console.log(`    ${cat.category} ${dim(cat.name.padEnd(42))} ${levelColor(cat.coverageLevel.padEnd(14))} ${cat.ruleCount} rules, ${cat.cwes.length} CWEs${findingSuffix}`);
    }

    // Extra rules
    const extra = owaspReport.categories.find((c) => c.category === 'EXTRA');
    if (extra) {
      console.log(`    ${'EXTRA'.padEnd(8)} ${dim(extra.name.padEnd(42))} ${dim(extra.coverageLevel.padEnd(14))} ${extra.ruleCount} rules`);
    }

    console.log();

    if (owaspReport.gaps.length > 0) {
      console.log(boldYellow('  Gaps:'));
      for (const g of owaspReport.gaps.slice(0, 10)) {
        console.log(`    ${yellow('!')} ${g}`);
      }
      console.log();
    }

    if (flags.has('--json')) {
      console.log(JSON.stringify(owaspReport, null, 2));
    }

    console.log();
    return;
  }

  // Normal scan mode
  log.header('Source Code Security Scan');
  console.log();

  log.info(`Scanning ${dir} with ${ALL_RULES.length} rules...`);
  console.log();

  const report = await scanProject({ dir, severityThreshold, confidenceThreshold });

  if (report.findings.length === 0) {
    log.success(`No findings in ${report.summary.totalFiles} files (${report.scanDurationMs}ms)`);
    console.log();
    return;
  }

  // Print findings
  const showFix = flags.has('--fix');
  const limit = 50;

  for (const f of report.findings.slice(0, limit)) {
    const sevColor = f.severity === 'critical' ? boldRed
      : f.severity === 'high' ? red
        : f.severity === 'medium' ? yellow : dim;

    console.log(`  ${sevColor(f.severity.toUpperCase().padEnd(8))} ${dim(f.file + ':' + f.line)} ${f.message}`);
    console.log(`           ${dim(f.owasp + ' | CWE-' + f.cwe + ' | ' + f.confidence + ' confidence')}`);

    if (f.snippet) {
      console.log(`           ${dim(f.snippet)}`);
    }

    if (showFix) {
      console.log(`           ${green('Fix:')} ${f.fix}`);
      console.log(`           ${dim('FP:')} ${dim(f.falsePositive)}`);
    }
    console.log();
  }

  if (report.findings.length > limit) {
    console.log(dim(`  ... and ${report.findings.length - limit} more findings`));
    console.log();
  }

  // Summary
  console.log(bold('  Summary:'));
  console.log(`    Files scanned:  ${report.summary.totalFiles}`);
  console.log(`    Findings:       ${report.summary.totalFindings}`);
  console.log(`    Risk score:     ${report.summary.riskScore}/100`);
  console.log(`    Duration:       ${report.scanDurationMs}ms`);
  console.log(`    Rules applied:  ${report.rulesApplied}`);
  console.log();

  console.log(`    ${boldRed(String(report.summary.bySeverity.critical))} critical  ${red(String(report.summary.bySeverity.high))} high  ${yellow(String(report.summary.bySeverity.medium))} medium  ${dim(String(report.summary.bySeverity.low))} low`);
  console.log();

  if (Object.keys(report.summary.byOWASP).length > 0) {
    console.log(bold('  OWASP Breakdown:'));
    for (const [cat, data] of Object.entries(report.summary.byOWASP)) {
      console.log(`    ${cat} ${dim(data.name.padEnd(40))} ${data.count} finding${data.count !== 1 ? 's' : ''}`);
    }
    console.log();
  }

  if (flags.has('--json')) {
    console.log(JSON.stringify(report, null, 2));
  }

  if (report.summary.bySeverity.critical > 0) {
    process.exitCode = 1;
  }
}

// ── Arg parsing ──────────────────────────────────────────────────────────

function parseArgs(argv: string[]): { command: string; args: string[]; flags: Set<string> } {
  const args: string[] = [];
  const flags = new Set<string>();

  for (const arg of argv.slice(2)) {
    if (arg.startsWith('--')) {
      flags.add(arg);
    } else {
      args.push(arg);
    }
  }

  return {
    command: args[0] ?? 'help',
    args: args.slice(1),
    flags,
  };
}

// ── Main ─────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { command, args, flags } = parseArgs(process.argv);

  if (flags.has('--verbose')) {
    log.setLevel('debug');
  }

  switch (command) {
    case 'install':
      if (!args[0]) {
        log.error('Missing package name. Usage: shieldpm install <package>');
        process.exitCode = 1;
        return;
      }
      await cmdInstall(args[0], flags);
      break;

    case 'audit':
      await cmdAudit(flags.has('--deep'), flags);
      break;

    case 'inspect':
      if (!args[0]) {
        log.error('Missing package name. Usage: shieldpm inspect <package>');
        process.exitCode = 1;
        return;
      }
      await cmdInspect(args[0]);
      break;

    case 'sandbox':
      await cmdSandbox(args);
      break;

    case 'manifest':
      if (args[0] === 'generate') {
        await cmdManifestGenerate();
      } else if (args[0] === 'enforce') {
        await cmdManifestEnforce();
      } else {
        log.error('Unknown manifest subcommand. Use: manifest generate | manifest enforce');
        process.exitCode = 1;
      }
      break;

    case 'diff':
      await cmdDiff();
      break;

    case 'sbom':
      await cmdSBOM(flags);
      break;

    case 'license':
      await cmdLicense(args[0] ?? 'scan');
      break;

    case 'policy':
      await cmdPolicy(args[0] ?? 'check');
      break;

    case 'lists':
    case 'list':
      await cmdLists(args[0] ?? 'show', args.slice(1));
      break;

    case 'compliance':
      await cmdCompliance(flags);
      break;

    case 'cicd':
      await cmdCICD(args);
      break;

    case 'hook':
      if (args[0] === 'install') {
        await cmdHookInstall();
      } else {
        log.error('Usage: shieldpm hook install');
        process.exitCode = 1;
      }
      break;

    case 'gate':
      await cmdGate(flags);
      break;

    case 'pr-comment':
      await cmdPRComment();
      break;

    case 'provenance':
      await cmdProvenance();
      break;

    case 'maintainer':
      await cmdMaintainer();
      break;

    case 'remediate':
      await cmdRemediate();
      break;

    case 'monitor':
      await cmdMonitor(args[0] ?? 'check');
      break;

    case 'posture':
      await cmdPosture(args[0] ?? 'trend');
      break;

    case 'report':
      await cmdReport(flags);
      break;

    case 'scan':
      await cmdScan(flags);
      break;

    case 'version':
    case '--version':
    case '-v':
      console.log(`shieldpm v${VERSION}`);
      break;

    case 'help':
    case '--help':
    case '-h':
      printHelp();
      break;

    default:
      log.error(`Unknown command: "${command}"`);
      console.log(dim('  Run "shieldpm help" for usage information.'));
      process.exitCode = 1;
      break;
  }
}

main().catch((err) => {
  log.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
