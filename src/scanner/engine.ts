/**
 * ShieldPM — Source Code Scanner Engine
 * Scans project source code against the OWASP pattern library.
 * Supports configurable extensions, ignore files, severity filtering,
 * deduplication, and OWASP category breakdown.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { join, extname, relative, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { ALL_RULES, OWASP_NAMES, type OWASPRule, type OWASPCategory, type Severity, type Confidence } from './patterns.js';

// ── Types ────────────────────────────────────────────────────────────────

export interface ScanFinding {
  ruleId: string;
  owasp: OWASPCategory;
  owaspName: string;
  cwe: number;
  severity: Severity;
  confidence: Confidence;
  message: string;
  description: string;
  fix: string;
  falsePositive: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  tags: string[];
}

export interface ScanSummary {
  totalFindings: number;
  totalFiles: number;
  filesWithFindings: number;
  bySeverity: Record<Severity, number>;
  byOWASP: Record<string, { name: string; count: number }>;
  byCWE: Record<number, number>;
  byConfidence: Record<Confidence, number>;
  topRules: Array<{ ruleId: string; count: number }>;
  riskScore: number;
}

export interface ScanReport {
  projectDir: string;
  timestamp: string;
  config: ScanConfig;
  findings: ScanFinding[];
  summary: ScanSummary;
  rulesApplied: number;
  scanDurationMs: number;
}

export interface ScanConfig {
  dir: string;
  extensions: string[];
  ignore: string[];
  severityThreshold: Severity;
  confidenceThreshold: Confidence;
  maxFiles: number;
  includeTests: boolean;
}

// ── Defaults ────────────────────────────────────────────────────────────

const DEFAULT_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx', '.json', '.html', '.vue', '.svelte'];

const DEFAULT_IGNORE = [
  'node_modules', '.git', 'dist', 'build', '.next', '.nuxt', '.svelte-kit',
  'coverage', '.shieldpm', '.cache', '.turbo', 'vendor',
  '*.min.js', '*.bundle.js', '*.map',
];

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };

export const DEFAULT_SCAN_CONFIG: ScanConfig = {
  dir: '.',
  extensions: DEFAULT_EXTENSIONS,
  ignore: DEFAULT_IGNORE,
  severityThreshold: 'low',
  confidenceThreshold: 'low',
  maxFiles: 5000,
  includeTests: false,
};

// ── .shieldpmignore Parser ──────────────────────────────────────────────

async function loadIgnorePatterns(projectDir: string): Promise<string[]> {
  const ignorePath = join(projectDir, '.shieldpmignore');
  const patterns: string[] = [...DEFAULT_IGNORE];

  try {
    const content = await readFile(ignorePath, 'utf-8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        patterns.push(trimmed);
      }
    }
  } catch { /* no ignore file — use defaults */ }

  return patterns;
}

function shouldIgnore(filePath: string, ignorePatterns: string[]): boolean {
  const parts = filePath.split('/');
  for (const pattern of ignorePatterns) {
    // Directory match
    if (!pattern.includes('*') && !pattern.includes('.')) {
      if (parts.some((p) => p === pattern)) return true;
    }
    // Extension match (*.min.js)
    if (pattern.startsWith('*.')) {
      if (filePath.endsWith(pattern.slice(1))) return true;
    }
    // Exact file match
    if (filePath.endsWith(pattern)) return true;
  }
  return false;
}

// ── File Collector ──────────────────────────────────────────────────────

async function collectFiles(
  dir: string,
  extensions: Set<string>,
  ignorePatterns: string[],
  maxFiles: number,
  includeTests: boolean
): Promise<string[]> {
  const files: string[] = [];
  const testDirs = new Set(['test', 'tests', '__tests__', '__mocks__', '__snapshots__', 'spec', 'specs']);

  async function walk(d: string): Promise<void> {
    if (files.length >= maxFiles) return;

    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      const full = join(d, entry.name);
      const rel = relative(dir, full);

      if (entry.isDirectory()) {
        if (shouldIgnore(rel, ignorePatterns)) continue;
        if (!includeTests && testDirs.has(entry.name)) continue;
        await walk(full);
      } else if (entry.isFile()) {
        if (shouldIgnore(rel, ignorePatterns)) continue;
        if (!extensions.has(extname(entry.name))) continue;
        // Skip test files unless includeTests
        if (!includeTests && /\.(test|spec|e2e)\.[jt]sx?$/.test(entry.name)) continue;
        files.push(full);
      }
    }
  }

  await walk(dir);
  return files;
}

// ── Core Scanner ────────────────────────────────────────────────────────

function scanContent(
  content: string,
  filePath: string,
  rules: OWASPRule[],
  sevThreshold: number,
  confThreshold: number,
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = content.split('\n');

  for (const rule of rules) {
    // Filter by severity/confidence threshold
    if (SEVERITY_ORDER[rule.severity] > sevThreshold) continue;
    if (CONFIDENCE_ORDER[rule.confidence] > confThreshold) continue;

    // Reset regex state
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = rule.pattern.exec(content)) !== null) {
      // Calculate line and column
      const beforeMatch = content.slice(0, match.index);
      const line = (beforeMatch.match(/\n/g) || []).length + 1;
      const lastNewline = beforeMatch.lastIndexOf('\n');
      const column = match.index - lastNewline;

      // Extract snippet
      const snippetLine = lines[line - 1]?.trim() ?? '';
      const snippet = snippetLine.length > 120 ? snippetLine.slice(0, 117) + '...' : snippetLine;

      findings.push({
        ruleId: rule.id,
        owasp: rule.owasp,
        owaspName: OWASP_NAMES[rule.owasp],
        cwe: rule.cwe,
        severity: rule.severity,
        confidence: rule.confidence,
        message: rule.message,
        description: rule.description,
        fix: rule.fix,
        falsePositive: rule.falsePositive,
        file: filePath,
        line,
        column,
        snippet,
        tags: rule.tags,
      });
    }
  }

  return findings;
}

// ── Deduplication ───────────────────────────────────────────────────────

function deduplicateFindings(findings: ScanFinding[]): ScanFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.ruleId}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ── Summary Generator ───────────────────────────────────────────────────

function buildSummary(findings: ScanFinding[], totalFiles: number): ScanSummary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byOWASP: Record<string, { name: string; count: number }> = {};
  const byCWE: Record<number, number> = {};
  const byConfidence: Record<Confidence, number> = { high: 0, medium: 0, low: 0 };
  const ruleCount: Record<string, number> = {};
  const filesWithFindings = new Set<string>();

  for (const f of findings) {
    bySeverity[f.severity]++;
    byConfidence[f.confidence]++;
    byCWE[f.cwe] = (byCWE[f.cwe] ?? 0) + 1;
    ruleCount[f.ruleId] = (ruleCount[f.ruleId] ?? 0) + 1;
    filesWithFindings.add(f.file);

    if (!byOWASP[f.owasp]) {
      byOWASP[f.owasp] = { name: f.owaspName, count: 0 };
    }
    byOWASP[f.owasp].count++;
  }

  const topRules = Object.entries(ruleCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ruleId, count]) => ({ ruleId, count }));

  // Risk score: 0-100 (higher = worse)
  const raw = bySeverity.critical * 10 + bySeverity.high * 5 + bySeverity.medium * 2 + bySeverity.low * 0.5;
  const riskScore = Math.min(100, Math.round(100 * (1 - Math.exp(-raw / 20))));

  return {
    totalFindings: findings.length,
    totalFiles,
    filesWithFindings: filesWithFindings.size,
    bySeverity,
    byOWASP,
    byCWE,
    byConfidence,
    topRules,
    riskScore,
  };
}

// ── Public API ──────────────────────────────────────────────────────────

export async function scanProject(config: Partial<ScanConfig> = {}): Promise<ScanReport> {
  const cfg: ScanConfig = { ...DEFAULT_SCAN_CONFIG, ...config };
  const projectDir = resolve(cfg.dir);
  const startTime = Date.now();

  const ignorePatterns = await loadIgnorePatterns(projectDir);
  const extensions = new Set(cfg.extensions);
  const sevThreshold = SEVERITY_ORDER[cfg.severityThreshold];
  const confThreshold = CONFIDENCE_ORDER[cfg.confidenceThreshold];

  // Collect files
  const files = await collectFiles(projectDir, extensions, [...ignorePatterns, ...cfg.ignore], cfg.maxFiles, cfg.includeTests);

  // Scan all files
  const allFindings: ScanFinding[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, 'utf-8');
    } catch { continue; }

    const relPath = relative(projectDir, file);
    const findings = scanContent(content, relPath, ALL_RULES, sevThreshold, confThreshold);
    allFindings.push(...findings);
  }

  // Dedup and sort
  const deduped = deduplicateFindings(allFindings);
  deduped.sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });

  const summary = buildSummary(deduped, files.length);

  return {
    projectDir,
    timestamp: new Date().toISOString(),
    config: cfg,
    findings: deduped,
    summary,
    rulesApplied: ALL_RULES.length,
    scanDurationMs: Date.now() - startTime,
  };
}

export async function scanFile(filePath: string, config: Partial<ScanConfig> = {}): Promise<ScanFinding[]> {
  const cfg: ScanConfig = { ...DEFAULT_SCAN_CONFIG, ...config };
  const sevThreshold = SEVERITY_ORDER[cfg.severityThreshold];
  const confThreshold = CONFIDENCE_ORDER[cfg.confidenceThreshold];

  let content: string;
  try {
    content = await readFile(filePath, 'utf-8');
  } catch {
    return [];
  }

  const findings = scanContent(content, filePath, ALL_RULES, sevThreshold, confThreshold);
  return deduplicateFindings(findings);
}
