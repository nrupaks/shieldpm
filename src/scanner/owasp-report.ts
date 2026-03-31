/**
 * ShieldPM — OWASP Coverage Report
 * Generates reports showing which OWASP Top 10 categories are covered,
 * CWE coverage matrix, compliance scoring, and gap analysis.
 */

import { ALL_RULES, OWASP_NAMES, getCategoryStats, getUniqueCWEs, type OWASPCategory, type OWASPRule } from './patterns.js';
import type { ScanReport, ScanSummary } from './engine.js';

// ── Types ────────────────────────────────────────────────────────────────

export interface OWASPCoverage {
  category: OWASPCategory;
  name: string;
  ruleCount: number;
  cwes: number[];
  severities: Record<string, number>;
  coverageLevel: 'comprehensive' | 'good' | 'basic' | 'minimal' | 'none';
}

export interface CWEEntry {
  cwe: number;
  name: string;
  ruleCount: number;
  owasp: OWASPCategory[];
}

export interface OWASPComplianceReport {
  timestamp: string;
  totalRules: number;
  totalCWEs: number;
  categories: OWASPCoverage[];
  cweMatrix: CWEEntry[];
  overallScore: number;
  overallLevel: string;
  gaps: string[];
  recommendations: string[];
  scanResults?: {
    findingsByCategory: Record<string, number>;
    riskScore: number;
    topIssues: Array<{ ruleId: string; count: number; severity: string }>;
  };
}

// ── CWE Names (common ones) ────────────────────────────────────────────

const CWE_NAMES: Record<number, string> = {
  20: 'Improper Input Validation',
  22: 'Path Traversal',
  78: 'OS Command Injection',
  79: 'Cross-site Scripting (XSS)',
  89: 'SQL Injection',
  90: 'LDAP Injection',
  94: 'Code Injection',
  95: 'Eval Injection',
  113: 'HTTP Response Splitting',
  117: 'Log Injection',
  209: 'Error Information Exposure',
  256: 'Cleartext Storage of Password',
  259: 'Hardcoded Password',
  269: 'Improper Privilege Management',
  295: 'Improper Certificate Validation',
  321: 'Hardcoded Cryptographic Key',
  326: 'Inadequate Encryption Strength',
  327: 'Broken Cryptographic Algorithm',
  338: 'Weak PRNG',
  345: 'Insufficient Verification of Data Authenticity',
  353: 'Missing Subresource Integrity',
  362: 'Race Condition',
  384: 'Session Fixation',
  390: 'Detection of Error Condition Without Action',
  427: 'Uncontrolled Search Path Element',
  457: 'Use of Uninitialized Variable',
  476: 'NULL Pointer Dereference',
  477: 'Use of Obsolete Function',
  489: 'Active Debug Code',
  494: 'Download of Code Without Integrity Check',
  502: 'Deserialization of Untrusted Data',
  521: 'Weak Password Requirements',
  532: 'Sensitive Information in Log Files',
  538: 'Insertion of Sensitive Information into Externally-Accessible File',
  548: 'Exposure of Information Through Directory Listing',
  598: 'Credentials in GET Request URL',
  601: 'Open Redirect',
  614: 'Sensitive Cookie Without Secure Flag',
  639: 'Authorization Bypass Through User-Controlled Key',
  643: 'XPath Injection',
  693: 'Protection Mechanism Failure',
  704: 'Incorrect Type Conversion',
  710: 'Improper Adherence to Coding Standards',
  749: 'Exposed Dangerous Method',
  770: 'Allocation of Resources Without Limits',
  778: 'Insufficient Logging',
  798: 'Hardcoded Credentials',
  829: 'Inclusion of Functionality from Untrusted Control Sphere',
  836: 'Use of Password Hash Instead of Password for Authentication',
  862: 'Missing Authorization',
  916: 'Use of Password Hash With Insufficient Effort',
  918: 'Server-Side Request Forgery',
  942: 'Permissive Cross-domain Policy',
  943: 'Improper Neutralization of Special Elements in Data Query Logic',
  1035: 'Using Components with Known Vulnerabilities',
  1104: 'Use of Unmaintained Third-Party Components',
  1188: 'Initialization with Hard-Coded Network Resource Configuration Default',
  1321: 'Improperly Controlled Modification of Object Prototype Attributes',
  1333: 'Inefficient Regular Expression Complexity',
  1393: 'Use of Default Credentials',
};

// ── Coverage Calculator ─────────────────────────────────────────────────

function getCoverageLevel(ruleCount: number): OWASPCoverage['coverageLevel'] {
  if (ruleCount >= 8) return 'comprehensive';
  if (ruleCount >= 5) return 'good';
  if (ruleCount >= 3) return 'basic';
  if (ruleCount >= 1) return 'minimal';
  return 'none';
}

export function calculateCoverage(): OWASPCoverage[] {
  const categories: OWASPCoverage[] = [];

  for (const [cat, name] of Object.entries(OWASP_NAMES) as [OWASPCategory, string][]) {
    const rules = ALL_RULES.filter((r) => r.owasp === cat);
    const cwes = [...new Set(rules.map((r) => r.cwe))];
    const severities: Record<string, number> = {};
    for (const r of rules) {
      severities[r.severity] = (severities[r.severity] ?? 0) + 1;
    }

    categories.push({
      category: cat,
      name,
      ruleCount: rules.length,
      cwes,
      severities,
      coverageLevel: getCoverageLevel(rules.length),
    });
  }

  return categories;
}

// ── CWE Matrix ──────────────────────────────────────────────────────────

export function buildCWEMatrix(): CWEEntry[] {
  const cweMap = new Map<number, { rules: OWASPRule[]; owasp: Set<OWASPCategory> }>();

  for (const rule of ALL_RULES) {
    if (!cweMap.has(rule.cwe)) {
      cweMap.set(rule.cwe, { rules: [], owasp: new Set() });
    }
    const entry = cweMap.get(rule.cwe)!;
    entry.rules.push(rule);
    entry.owasp.add(rule.owasp);
  }

  return [...cweMap.entries()]
    .map(([cwe, { rules, owasp }]) => ({
      cwe,
      name: CWE_NAMES[cwe] ?? `CWE-${cwe}`,
      ruleCount: rules.length,
      owasp: [...owasp],
    }))
    .sort((a, b) => a.cwe - b.cwe);
}

// ── Gap Analysis ────────────────────────────────────────────────────────

function analyzeGaps(categories: OWASPCoverage[]): { gaps: string[]; recommendations: string[] } {
  const gaps: string[] = [];
  const recommendations: string[] = [];

  for (const cat of categories) {
    if (cat.category === 'EXTRA') continue;

    if (cat.coverageLevel === 'none') {
      gaps.push(`${cat.category} ${cat.name}: No rules defined`);
      recommendations.push(`Add detection rules for ${cat.name}`);
    } else if (cat.coverageLevel === 'minimal') {
      gaps.push(`${cat.category} ${cat.name}: Only ${cat.ruleCount} rule(s) — minimal coverage`);
      recommendations.push(`Expand ${cat.name} rules to at least 5 for basic coverage`);
    }

    if (cat.cwes.length < 2 && cat.ruleCount > 0) {
      gaps.push(`${cat.category} ${cat.name}: Only ${cat.cwes.length} unique CWE(s) covered`);
    }
  }

  // Check for missing critical CWEs
  const coveredCWEs = new Set(ALL_RULES.map((r) => r.cwe));
  const criticalCWEs = [79, 89, 78, 22, 918, 502, 798, 327, 862];
  for (const cwe of criticalCWEs) {
    if (!coveredCWEs.has(cwe)) {
      gaps.push(`CWE-${cwe} (${CWE_NAMES[cwe] ?? 'Unknown'}): Not covered by any rule`);
      recommendations.push(`Add rules for CWE-${cwe}`);
    }
  }

  return { gaps, recommendations };
}

// ── Compliance Score ────────────────────────────────────────────────────

function calculateComplianceScore(categories: OWASPCoverage[]): { score: number; level: string } {
  const owaspCategories = categories.filter((c) => c.category !== 'EXTRA');
  const levelScores: Record<string, number> = {
    comprehensive: 100, good: 75, basic: 50, minimal: 25, none: 0,
  };

  const totalScore = owaspCategories.reduce((sum, c) => sum + levelScores[c.coverageLevel], 0);
  const score = Math.round(totalScore / owaspCategories.length);

  const level = score >= 80 ? 'Strong' : score >= 60 ? 'Moderate' : score >= 40 ? 'Basic' : 'Weak';

  return { score, level };
}

// ── Public API ──────────────────────────────────────────────────────────

export function generateOWASPReport(scanReport?: ScanReport): OWASPComplianceReport {
  const categories = calculateCoverage();
  const cweMatrix = buildCWEMatrix();
  const { gaps, recommendations } = analyzeGaps(categories);
  const { score, level } = calculateComplianceScore(categories);

  const report: OWASPComplianceReport = {
    timestamp: new Date().toISOString(),
    totalRules: ALL_RULES.length,
    totalCWEs: getUniqueCWEs().length,
    categories,
    cweMatrix,
    overallScore: score,
    overallLevel: level,
    gaps,
    recommendations,
  };

  // Attach scan results if provided
  if (scanReport) {
    const findingsByCategory: Record<string, number> = {};
    for (const f of scanReport.findings) {
      findingsByCategory[f.owasp] = (findingsByCategory[f.owasp] ?? 0) + 1;
    }

    report.scanResults = {
      findingsByCategory,
      riskScore: scanReport.summary.riskScore,
      topIssues: scanReport.summary.topRules.map((r) => {
        const rule = ALL_RULES.find((ar) => ar.id === r.ruleId);
        return { ruleId: r.ruleId, count: r.count, severity: rule?.severity ?? 'medium' };
      }),
    };
  }

  return report;
}

export { CWE_NAMES };
