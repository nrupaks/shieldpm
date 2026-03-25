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

import { bold, cyan, red, green, yellow, dim, boldRed, boldGreen, boldYellow, boldCyan } from './utils/colors.js';
import log from './utils/logger.js';
import { analyzePackage, type RiskReport, type Finding } from './analyzer/static.js';
import { checkTyposquatting, type TyposquatResult } from './analyzer/typosquat.js';
import { runSandboxed, type SandboxResult } from './sandbox/runner.js';
import { loadManifest, saveManifest, generateManifest, validateAccess, type PermissionManifest } from './monitor/permissions.js';
import { generateProfile, diffProfiles, saveProfile, loadProfile } from './fingerprint/profile.js';
import { diffLockfilesByPath, diffLockfiles } from './diff/dependency.js';

// ── Version ──────────────────────────────────────────────────────────────

const VERSION = '0.1.0';

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
    totalScore += report.score;

    if (report.score > maxScore) {
      maxScore = report.score;
      maxPkg = dep;
    }

    const scoreStr = report.score >= 7
      ? boldRed(report.score.toFixed(1))
      : report.score >= 4
        ? boldYellow(report.score.toFixed(1))
        : boldGreen(report.score.toFixed(1));

    console.log(`  ${scoreStr.padStart(18)} ${dep} ${dim(`(${report.findings.length} findings)`)}`);

    if (report.score >= 4) {
      highRisk.push({ name: dep, score: report.score });
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
