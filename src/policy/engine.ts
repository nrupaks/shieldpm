/**
 * ShieldPM — Policy-as-Code Engine
 * Define and enforce security policies for dependencies using declarative rules.
 * Policies are defined in shieldpm-policy.json with a flexible rule system.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────

export type PolicyOperator = 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq' | 'in' | 'not-in' | 'contains' | 'matches';

export type PolicyAction = 'block' | 'warn' | 'audit';

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  field: string;
  operator: PolicyOperator;
  value: string | number | boolean | string[];
  action: PolicyAction;
  severity: 'critical' | 'high' | 'medium' | 'low';
  enabled: boolean;
}

export interface PolicyDocument {
  version: 1;
  name: string;
  description: string;
  rules: PolicyRule[];
  createdAt: string;
  updatedAt: string;
}

export interface PolicyContext {
  packageName: string;
  version: string;
  license: string;
  riskScore: number;
  hasInstallScripts: boolean;
  hasNativeModules: boolean;
  dependencyCount: number;
  weeklyDownloads: number;
  lastPublished: string;
  maintainerCount: number;
  isNew: boolean;
  categories: string[];
  findingCount: number;
  criticalFindings: number;
  highFindings: number;
}

export interface PolicyResult {
  ruleId: string;
  ruleName: string;
  passed: boolean;
  action: PolicyAction;
  severity: string;
  message: string;
  context: { field: string; actual: unknown; expected: unknown };
}

export interface PolicyEvaluation {
  packageName: string;
  results: PolicyResult[];
  blocked: boolean;
  warnings: number;
  passed: number;
  failed: number;
  timestamp: string;
}

// ── Default Policy ──────────────────────────────────────────────────────

export const DEFAULT_POLICY: PolicyDocument = {
  version: 1,
  name: 'default',
  description: 'Default ShieldPM security policy',
  rules: [
    {
      id: 'max-risk-score',
      name: 'Maximum Risk Score',
      description: 'Block packages with risk score above threshold',
      field: 'riskScore',
      operator: 'lte',
      value: 7,
      action: 'block',
      severity: 'critical',
      enabled: true,
    },
    {
      id: 'no-install-scripts',
      name: 'No Install Scripts',
      description: 'Warn on packages with preinstall/postinstall scripts',
      field: 'hasInstallScripts',
      operator: 'eq',
      value: false,
      action: 'warn',
      severity: 'medium',
      enabled: true,
    },
    {
      id: 'no-critical-findings',
      name: 'No Critical Findings',
      description: 'Block packages with critical security findings',
      field: 'criticalFindings',
      operator: 'eq',
      value: 0,
      action: 'block',
      severity: 'critical',
      enabled: true,
    },
    {
      id: 'known-license',
      name: 'Known License Required',
      description: 'Warn on packages without a recognized license',
      field: 'license',
      operator: 'neq',
      value: 'UNKNOWN',
      action: 'warn',
      severity: 'medium',
      enabled: true,
    },
    {
      id: 'no-copyleft',
      name: 'No Copyleft Licenses',
      description: 'Warn on packages with copyleft licenses',
      field: 'license',
      operator: 'not-in',
      value: ['GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only', 'AGPL-3.0-or-later'],
      action: 'warn',
      severity: 'high',
      enabled: false,
    },
    {
      id: 'max-findings',
      name: 'Maximum Findings',
      description: 'Warn when package has more than 20 findings',
      field: 'findingCount',
      operator: 'lte',
      value: 20,
      action: 'warn',
      severity: 'medium',
      enabled: true,
    },
  ],
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

// ── Policy I/O ──────────────────────────────────────────────────────────

const POLICY_FILENAME = 'shieldpm-policy.json';

export async function loadPolicy(dir?: string): Promise<PolicyDocument> {
  const path = join(dir ?? process.cwd(), POLICY_FILENAME);
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed = JSON.parse(raw);
    if (!parsed.rules || !Array.isArray(parsed.rules)) {
      throw new Error('Invalid policy: missing "rules" array');
    }
    return parsed as PolicyDocument;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return DEFAULT_POLICY;
    }
    throw err;
  }
}

export async function savePolicy(policy: PolicyDocument, dir?: string): Promise<string> {
  const path = join(dir ?? process.cwd(), POLICY_FILENAME);
  policy.updatedAt = new Date().toISOString();
  await writeFile(path, JSON.stringify(policy, null, 2) + '\n', 'utf-8');
  return path;
}

export async function initPolicy(dir?: string): Promise<string> {
  return savePolicy({ ...DEFAULT_POLICY, createdAt: new Date().toISOString() }, dir);
}

// ── Rule Evaluation ─────────────────────────────────────────────────────

function evaluateRule(rule: PolicyRule, context: PolicyContext): PolicyResult {
  const actual = getFieldValue(context, rule.field);
  const expected = rule.value;
  let passed = false;

  switch (rule.operator) {
    case 'gt':
      passed = typeof actual === 'number' && actual > (expected as number);
      break;
    case 'gte':
      passed = typeof actual === 'number' && actual >= (expected as number);
      break;
    case 'lt':
      passed = typeof actual === 'number' && actual < (expected as number);
      break;
    case 'lte':
      passed = typeof actual === 'number' && actual <= (expected as number);
      break;
    case 'eq':
      passed = actual === expected;
      break;
    case 'neq':
      passed = actual !== expected;
      break;
    case 'in':
      passed = Array.isArray(expected) && expected.includes(actual as string);
      break;
    case 'not-in':
      passed = Array.isArray(expected) && !expected.includes(actual as string);
      break;
    case 'contains':
      passed = typeof actual === 'string' && actual.includes(expected as string);
      break;
    case 'matches':
      try {
        passed = typeof actual === 'string' && new RegExp(expected as string).test(actual);
      } catch {
        passed = false;
      }
      break;
  }

  return {
    ruleId: rule.id,
    ruleName: rule.name,
    passed,
    action: rule.action,
    severity: rule.severity,
    message: passed
      ? `${rule.name}: passed`
      : `${rule.name}: ${rule.description} (${rule.field} = ${JSON.stringify(actual)}, expected ${rule.operator} ${JSON.stringify(expected)})`,
    context: { field: rule.field, actual, expected },
  };
}

function getFieldValue(context: PolicyContext, field: string): unknown {
  return (context as unknown as Record<string, unknown>)[field] ?? null;
}

// ── Policy Evaluation ───────────────────────────────────────────────────

export function evaluatePolicy(policy: PolicyDocument, context: PolicyContext): PolicyEvaluation {
  const results: PolicyResult[] = [];

  for (const rule of policy.rules) {
    if (!rule.enabled) continue;
    results.push(evaluateRule(rule, context));
  }

  const blocked = results.some((r) => !r.passed && r.action === 'block');
  const warnings = results.filter((r) => !r.passed && r.action === 'warn').length;
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  return {
    packageName: context.packageName,
    results,
    blocked,
    warnings,
    passed,
    failed,
    timestamp: new Date().toISOString(),
  };
}

export function buildPolicyContext(
  packageName: string,
  opts: Partial<PolicyContext>
): PolicyContext {
  return {
    packageName,
    version: '0.0.0',
    license: 'UNKNOWN',
    riskScore: 0,
    hasInstallScripts: false,
    hasNativeModules: false,
    dependencyCount: 0,
    weeklyDownloads: 0,
    lastPublished: '',
    maintainerCount: 0,
    isNew: false,
    categories: [],
    findingCount: 0,
    criticalFindings: 0,
    highFindings: 0,
    ...opts,
  };
}
