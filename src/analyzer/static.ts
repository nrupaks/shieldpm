/**
 * ShieldPM — Static Analysis Engine
 * Scans package source code for suspicious patterns, network calls,
 * filesystem access, obfuscation, and dynamic code execution.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, extname, relative } from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  severity: Severity;
  category: string;
  message: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  rule: string;
}

export interface RiskReport {
  /** Overall risk score 0 (safe) – 10 (dangerous) */
  score: number;
  findings: Finding[];
  summary: string;
  /** Breakdown by category */
  categoryCounts: Record<string, number>;
  /** Total files scanned */
  filesScanned: number;
}

// ── Pattern definitions ──────────────────────────────────────────────────

interface PatternRule {
  rule: string;
  pattern: RegExp;
  severity: Severity;
  category: string;
  message: string;
}

const PATTERNS: PatternRule[] = [
  // ── Dynamic code execution ──
  {
    rule: 'no-eval',
    pattern: /\beval\s*\(/g,
    severity: 'critical',
    category: 'code-execution',
    message: 'eval() can execute arbitrary code',
  },
  {
    rule: 'no-function-constructor',
    pattern: /\bnew\s+Function\s*\(/g,
    severity: 'critical',
    category: 'code-execution',
    message: 'Function constructor can execute arbitrary code',
  },
  {
    rule: 'no-vm-runInContext',
    pattern: /\bvm\s*\.\s*(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(/g,
    severity: 'high',
    category: 'code-execution',
    message: 'vm module can execute arbitrary code',
  },
  {
    rule: 'no-buffer-eval',
    pattern: /Buffer\.from\s*\([^)]+\)\s*\.\s*toString\s*\([^)]*\)[\s\S]{0,50}eval/g,
    severity: 'critical',
    category: 'code-execution',
    message: 'Buffer decode + eval pattern — likely obfuscated code execution',
  },

  // ── Child process / shell ──
  {
    rule: 'no-child-process',
    pattern: /require\s*\(\s*['"`]child_process['"`]\s*\)/g,
    severity: 'high',
    category: 'process',
    message: 'child_process can spawn arbitrary system commands',
  },
  {
    rule: 'no-child-process-import',
    pattern: /from\s+['"`]child_process['"`]/g,
    severity: 'high',
    category: 'process',
    message: 'child_process import — can spawn arbitrary system commands',
  },
  {
    rule: 'no-exec-sync',
    pattern: /\b(execSync|exec|spawn|spawnSync|fork|execFile|execFileSync)\s*\(/g,
    severity: 'high',
    category: 'process',
    message: 'Process execution function detected',
  },

  // ── Network access ──
  {
    rule: 'no-http-require',
    pattern: /require\s*\(\s*['"`](https?|net|tls|dgram)['"`]\s*\)/g,
    severity: 'medium',
    category: 'network',
    message: 'Network module require',
  },
  {
    rule: 'no-http-import',
    pattern: /from\s+['"`](https?|net|tls|dgram)['"`]/g,
    severity: 'medium',
    category: 'network',
    message: 'Network module import',
  },
  {
    rule: 'no-http-request',
    pattern: /\b(https?)\s*\.\s*(request|get)\s*\(/g,
    severity: 'medium',
    category: 'network',
    message: 'HTTP request detected',
  },
  {
    rule: 'no-fetch',
    pattern: /\bfetch\s*\(\s*['"`]https?:/g,
    severity: 'medium',
    category: 'network',
    message: 'fetch() call to external URL',
  },
  {
    rule: 'no-fetch-dynamic',
    pattern: /\bfetch\s*\(\s*[^'"`\s]/g,
    severity: 'high',
    category: 'network',
    message: 'fetch() with dynamic URL — destination unknown',
  },
  {
    rule: 'no-dns-lookup',
    pattern: /\bdns\s*\.\s*(lookup|resolve|resolve4|resolve6)\s*\(/g,
    severity: 'low',
    category: 'network',
    message: 'DNS lookup detected',
  },
  {
    rule: 'no-xmlhttprequest',
    pattern: /\bnew\s+XMLHttpRequest\s*\(/g,
    severity: 'medium',
    category: 'network',
    message: 'XMLHttpRequest detected',
  },
  {
    rule: 'no-websocket',
    pattern: /\bnew\s+WebSocket\s*\(/g,
    severity: 'medium',
    category: 'network',
    message: 'WebSocket connection detected',
  },

  // ── File system access ──
  {
    rule: 'no-fs-require',
    pattern: /require\s*\(\s*['"`]fs['"`]\s*\)/g,
    severity: 'low',
    category: 'filesystem',
    message: 'fs module require',
  },
  {
    rule: 'no-fs-import',
    pattern: /from\s+['"`](fs|node:fs|fs\/promises|node:fs\/promises)['"`]/g,
    severity: 'low',
    category: 'filesystem',
    message: 'fs module import',
  },
  {
    rule: 'no-sensitive-path-read',
    pattern: /\b(readFile|readFileSync|createReadStream)\s*\(\s*['"`](\/etc\/passwd|\/etc\/shadow|~\/\.ssh|~\/\.aws|~\/\.npmrc|~\/\.env|\/proc\/)/g,
    severity: 'critical',
    category: 'filesystem',
    message: 'Reading sensitive system file',
  },
  {
    rule: 'no-sensitive-path-write',
    pattern: /\b(writeFile|writeFileSync|appendFile|appendFileSync)\s*\(\s*['"`](\/etc\/|\/usr\/|\/bin\/|~\/\.bashrc|~\/\.profile)/g,
    severity: 'critical',
    category: 'filesystem',
    message: 'Writing to sensitive system path',
  },
  {
    rule: 'no-fs-unlink',
    pattern: /\b(unlink|unlinkSync|rmdir|rmdirSync|rm)\s*\(/g,
    severity: 'medium',
    category: 'filesystem',
    message: 'File/directory deletion detected',
  },
  {
    rule: 'no-home-dir-readdir',
    pattern: /\b(readdir|readdirSync)\s*\(\s*['"`](~|\/home\/|\/Users\/)/g,
    severity: 'high',
    category: 'filesystem',
    message: 'Listing home directory contents',
  },

  // ── Environment variable access ──
  {
    rule: 'no-env-access',
    pattern: /process\.env\b/g,
    severity: 'low',
    category: 'environment',
    message: 'Accesses environment variables',
  },
  {
    rule: 'no-env-sensitive',
    pattern: /process\.env\s*\[\s*['"`](API_KEY|SECRET|TOKEN|PASSWORD|AWS_|GITHUB_TOKEN|NPM_TOKEN|DATABASE_URL|PRIVATE_KEY)/g,
    severity: 'high',
    category: 'environment',
    message: 'Accesses sensitive environment variable',
  },
  {
    rule: 'no-env-exfiltrate',
    pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)/g,
    severity: 'critical',
    category: 'environment',
    message: 'Serializing entire process.env — possible credential exfiltration',
  },

  // ── Dynamic require / import ──
  {
    rule: 'no-dynamic-require',
    pattern: /require\s*\(\s*[^'"`\s)][^)]*\)/g,
    severity: 'medium',
    category: 'code-execution',
    message: 'Dynamic require with non-literal argument',
  },
  {
    rule: 'no-dynamic-import',
    pattern: /import\s*\(\s*[^'"`\s)][^)]*\)/g,
    severity: 'medium',
    category: 'code-execution',
    message: 'Dynamic import with non-literal argument',
  },

  // ── Obfuscation ──
  {
    rule: 'no-charcode-build',
    pattern: /String\.fromCharCode\s*\(/g,
    severity: 'high',
    category: 'obfuscation',
    message: 'String.fromCharCode — common obfuscation technique',
  },
  {
    rule: 'no-hex-string',
    pattern: /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}/g,
    severity: 'high',
    category: 'obfuscation',
    message: 'Long hex escape sequence — possible obfuscated string',
  },
  {
    rule: 'no-unicode-escape',
    pattern: /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){5,}/g,
    severity: 'high',
    category: 'obfuscation',
    message: 'Long unicode escape sequence — possible obfuscated string',
  },
  {
    rule: 'no-atob',
    pattern: /\batob\s*\(/g,
    severity: 'medium',
    category: 'obfuscation',
    message: 'Base64 decode — may hide malicious strings',
  },
  {
    rule: 'no-base64-decode',
    pattern: /Buffer\.from\s*\([^,]+,\s*['"`]base64['"`]\s*\)/g,
    severity: 'medium',
    category: 'obfuscation',
    message: 'Base64 decode via Buffer — may hide malicious strings',
  },

  // ── Prototype pollution ──
  {
    rule: 'no-proto-access',
    pattern: /\[['"`]__proto__['"`]\]/g,
    severity: 'high',
    category: 'prototype-pollution',
    message: '__proto__ access — possible prototype pollution',
  },
  {
    rule: 'no-constructor-prototype',
    pattern: /\bconstructor\s*\[\s*['"`]prototype['"`]\s*\]/g,
    severity: 'high',
    category: 'prototype-pollution',
    message: 'constructor.prototype access — possible prototype pollution',
  },

  // ── Install scripts ──
  {
    rule: 'no-preinstall-script',
    pattern: /"preinstall"\s*:\s*"/g,
    severity: 'high',
    category: 'install-script',
    message: 'preinstall script can execute code before user reviews package',
  },
  {
    rule: 'no-postinstall-script',
    pattern: /"postinstall"\s*:\s*"/g,
    severity: 'medium',
    category: 'install-script',
    message: 'postinstall script detected',
  },
];

// ── Severity weights for scoring ─────────────────────────────────────────

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 3.0,
  high: 2.0,
  medium: 1.0,
  low: 0.3,
  info: 0.0,
};

// ── File collection ──────────────────────────────────────────────────────

const SCANNABLE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.json']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.shieldpm']);

async function collectFiles(dir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(d: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return; // skip unreadable dirs
    }
    for (const entry of entries) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          await walk(full);
        }
      } else if (entry.isFile() && SCANNABLE_EXTENSIONS.has(extname(entry.name))) {
        files.push(full);
      }
    }
  }

  await walk(dir);
  return files;
}

// ── Core scan logic ──────────────────────────────────────────────────────

function scanContent(content: string, filePath: string, rules: PatternRule[]): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const rule of rules) {
    // Reset lastIndex for global regexes
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = rule.pattern.exec(content)) !== null) {
      // Calculate line and column
      const beforeMatch = content.slice(0, match.index);
      const line = (beforeMatch.match(/\n/g) || []).length + 1;
      const lastNewline = beforeMatch.lastIndexOf('\n');
      const column = match.index - lastNewline;

      // Grab the snippet (the matched line)
      const snippet = lines[line - 1]?.trim() ?? '';

      findings.push({
        severity: rule.severity,
        category: rule.category,
        message: rule.message,
        file: filePath,
        line,
        column,
        snippet: snippet.length > 120 ? snippet.slice(0, 117) + '...' : snippet,
        rule: rule.rule,
      });
    }
  }

  return findings;
}

// ── Risk score calculation ───────────────────────────────────────────────

function calculateScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  let raw = 0;
  for (const f of findings) {
    raw += SEVERITY_WEIGHT[f.severity];
  }

  // Diminishing returns — many low findings shouldn't max the score
  // Score = 10 * (1 - e^(-raw/8))
  const score = 10 * (1 - Math.exp(-raw / 8));
  return Math.round(score * 10) / 10; // one decimal
}

function buildSummary(findings: Finding[], score: number): string {
  if (findings.length === 0) return 'No suspicious patterns found.';

  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;

  const parts: string[] = [];
  if (critical > 0) parts.push(`${critical} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (medium > 0) parts.push(`${medium} medium`);
  if (low > 0) parts.push(`${low} low`);

  const riskLabel = score >= 7 ? 'DANGEROUS' : score >= 4 ? 'SUSPICIOUS' : score >= 2 ? 'CAUTION' : 'LOW RISK';

  return `Risk: ${riskLabel} (${score}/10) — ${findings.length} findings: ${parts.join(', ')}`;
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Analyze a package directory for security risks via static pattern matching.
 */
export async function analyzePackage(packageDir: string): Promise<RiskReport> {
  const files = await collectFiles(packageDir);
  const allFindings: Finding[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = await readFile(file, 'utf-8');
    } catch {
      continue;
    }

    const relPath = relative(packageDir, file);
    const findings = scanContent(content, relPath, PATTERNS);
    allFindings.push(...findings);
  }

  // Deduplicate same rule+file+line
  const seen = new Set<string>();
  const deduped = allFindings.filter((f) => {
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort: critical first, then by file/line
  deduped.sort((a, b) => {
    const sw = SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
    if (sw !== 0) return sw;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });

  const score = calculateScore(deduped);

  const categoryCounts: Record<string, number> = {};
  for (const f of deduped) {
    categoryCounts[f.category] = (categoryCounts[f.category] ?? 0) + 1;
  }

  return {
    score,
    findings: deduped,
    summary: buildSummary(deduped, score),
    categoryCounts,
    filesScanned: files.length,
  };
}

/**
 * Analyze a single source string (useful for quick checks).
 */
export function analyzeSource(source: string, filename = '<input>'): Finding[] {
  return scanContent(source, filename, PATTERNS);
}
