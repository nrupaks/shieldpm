/**
 * ShieldPM — Patch Suggestions & Remediation
 * Suggests alternative packages, version upgrades, and temporary patches
 * for packages with security issues.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { RiskReport, Finding } from '../analyzer/static.js';

// ── Types ────────────────────────────────────────────────────────────────

export type RemediationType = 'upgrade' | 'replace' | 'configure' | 'remove' | 'monitor';

export interface PatchSuggestion {
  packageName: string;
  currentVersion: string;
  type: RemediationType;
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  action: string;
  alternative?: AlternativePackage;
  effort: 'trivial' | 'low' | 'medium' | 'high';
}

export interface AlternativePackage {
  name: string;
  description: string;
  reason: string;
  migrationComplexity: 'drop-in' | 'minor-changes' | 'significant-refactor';
}

export interface RemediationReport {
  packages: PackageRemediation[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    estimatedEffort: string;
  };
  timestamp: string;
}

export interface PackageRemediation {
  packageName: string;
  version: string;
  riskScore: number;
  suggestions: PatchSuggestion[];
}

// ── Known Alternatives Database ─────────────────────────────────────────

const ALTERNATIVES: Record<string, AlternativePackage[]> = {
  'request': [
    { name: 'node-fetch', description: 'Lightweight fetch API for Node.js', reason: 'request is deprecated', migrationComplexity: 'minor-changes' },
    { name: 'axios', description: 'Promise-based HTTP client', reason: 'Active maintenance, wide adoption', migrationComplexity: 'minor-changes' },
    { name: 'got', description: 'Human-friendly HTTP request library', reason: 'Modern API, TypeScript support', migrationComplexity: 'minor-changes' },
  ],
  'moment': [
    { name: 'dayjs', description: 'Lightweight date library (2KB)', reason: 'moment is in maintenance mode, dayjs is API-compatible', migrationComplexity: 'drop-in' },
    { name: 'date-fns', description: 'Modern date utility library', reason: 'Tree-shakeable, immutable', migrationComplexity: 'minor-changes' },
    { name: 'luxon', description: 'DateTime library by moment team', reason: 'Modern successor to moment', migrationComplexity: 'significant-refactor' },
  ],
  'underscore': [
    { name: 'lodash', description: 'Modern utility library', reason: 'Superset of underscore, better performance', migrationComplexity: 'drop-in' },
  ],
  'colors': [
    { name: 'chalk', description: 'Terminal string styling', reason: 'colors had a supply chain incident', migrationComplexity: 'minor-changes' },
    { name: 'picocolors', description: 'Tiny terminal colors (3.5x faster than chalk)', reason: 'Zero dependencies, fast', migrationComplexity: 'minor-changes' },
  ],
  'event-stream': [
    { name: 'highland', description: 'High-level streams library', reason: 'event-stream was compromised', migrationComplexity: 'significant-refactor' },
  ],
  'node-uuid': [
    { name: 'uuid', description: 'RFC-compliant UUID generation', reason: 'node-uuid is deprecated, renamed to uuid', migrationComplexity: 'drop-in' },
  ],
  'querystring': [
    { name: 'qs', description: 'Query string parser with security', reason: 'Built-in querystring is legacy', migrationComplexity: 'minor-changes' },
    { name: 'URLSearchParams', description: 'Built-in Web API', reason: 'No dependency needed', migrationComplexity: 'minor-changes' },
  ],
  'rimraf': [
    { name: 'fs.rm', description: 'Node.js built-in recursive remove', reason: 'Available since Node 14.14', migrationComplexity: 'minor-changes' },
  ],
  'mkdirp': [
    { name: 'fs.mkdir', description: 'Node.js built-in with recursive option', reason: 'Available since Node 10.12', migrationComplexity: 'drop-in' },
  ],
  'glob': [
    { name: 'fast-glob', description: 'Faster alternative to glob', reason: 'Better performance, maintained', migrationComplexity: 'minor-changes' },
    { name: 'tinyglobby', description: 'Tiny globbing utility', reason: 'Minimal footprint', migrationComplexity: 'minor-changes' },
  ],
};

// ── Category-based Suggestions ──────────────────────────────────────────

const CATEGORY_ACTIONS: Record<string, { title: string; description: string; action: string; type: RemediationType }> = {
  'code-execution': {
    title: 'Restrict dynamic code execution',
    description: 'Package uses eval(), Function(), or vm module which can execute arbitrary code',
    action: 'Add to permission manifest with exec:false. Review code for legitimate use cases.',
    type: 'configure',
  },
  'network': {
    title: 'Restrict network access',
    description: 'Package makes network requests that could exfiltrate data',
    action: 'Define allowed network destinations in permission manifest (shieldpm.json).',
    type: 'configure',
  },
  'filesystem': {
    title: 'Restrict filesystem access',
    description: 'Package accesses the filesystem, potentially reading sensitive files',
    action: 'Define allowed filesystem paths in permission manifest.',
    type: 'configure',
  },
  'environment': {
    title: 'Restrict environment access',
    description: 'Package reads environment variables, possibly harvesting credentials',
    action: 'Specify allowed env vars in permission manifest. Audit which vars are actually needed.',
    type: 'configure',
  },
  'process': {
    title: 'Restrict process spawning',
    description: 'Package can spawn child processes to execute system commands',
    action: 'Set exec:false in permission manifest unless process spawning is required.',
    type: 'configure',
  },
  'obfuscation': {
    title: 'Investigate obfuscated code',
    description: 'Package contains obfuscated code patterns that may hide malicious behavior',
    action: 'Manually review the obfuscated code. Consider using an alternative package.',
    type: 'monitor',
  },
  'prototype-pollution': {
    title: 'Mitigate prototype pollution',
    description: 'Package contains patterns that could enable prototype pollution attacks',
    action: 'Use Object.freeze() on prototypes, or replace with a safer alternative.',
    type: 'configure',
  },
  'install-script': {
    title: 'Sandbox install scripts',
    description: 'Package has install scripts that run before you can review the code',
    action: 'Use shieldpm install to run install scripts in a sandbox.',
    type: 'configure',
  },
};

// ── Suggestion Generation ───────────────────────────────────────────────

export function generateSuggestions(
  packageName: string,
  version: string,
  report: RiskReport
): PatchSuggestion[] {
  const suggestions: PatchSuggestion[] = [];

  // Check for known alternatives
  const alternatives = ALTERNATIVES[packageName];
  if (alternatives && alternatives.length > 0) {
    const best = alternatives[0];
    suggestions.push({
      packageName,
      currentVersion: version,
      type: 'replace',
      priority: report.score >= 7 ? 'critical' : 'high',
      title: `Replace ${packageName} with ${best.name}`,
      description: best.reason,
      action: `npm uninstall ${packageName} && npm install ${best.name}`,
      alternative: best,
      effort: best.migrationComplexity === 'drop-in' ? 'trivial'
        : best.migrationComplexity === 'minor-changes' ? 'low'
          : 'medium',
    });
  }

  // Generate category-based suggestions
  const categories = new Set(report.findings.map((f) => f.category));
  for (const category of categories) {
    const action = CATEGORY_ACTIONS[category];
    if (!action) continue;

    const categoryFindings = report.findings.filter((f) => f.category === category);
    const maxSeverity = categoryFindings.some((f) => f.severity === 'critical') ? 'critical'
      : categoryFindings.some((f) => f.severity === 'high') ? 'high'
        : 'medium';

    suggestions.push({
      packageName,
      currentVersion: version,
      type: action.type,
      priority: maxSeverity,
      title: action.title,
      description: `${action.description} (${categoryFindings.length} finding${categoryFindings.length !== 1 ? 's' : ''})`,
      action: action.action,
      effort: 'low',
    });
  }

  // If score is very high and no alternatives, suggest removal
  if (report.score >= 8 && !alternatives) {
    suggestions.push({
      packageName,
      currentVersion: version,
      type: 'remove',
      priority: 'critical',
      title: `Consider removing ${packageName}`,
      description: `Risk score ${report.score}/10 is dangerously high with no known safe alternatives`,
      action: `npm uninstall ${packageName}. Find a replacement or implement the functionality directly.`,
      effort: 'high',
    });
  }

  // Always suggest monitoring for any non-trivial findings
  if (report.score >= 2) {
    suggestions.push({
      packageName,
      currentVersion: version,
      type: 'monitor',
      priority: 'low',
      title: `Pin and monitor ${packageName}`,
      description: 'Pin exact version and monitor for behavioral changes',
      action: `Use exact version in package.json: "${packageName}": "${version}"`,
      effort: 'trivial',
    });
  }

  return suggestions.sort((a, b) => {
    const priority = { critical: 0, high: 1, medium: 2, low: 3 };
    return priority[a.priority] - priority[b.priority];
  });
}

// ── Remediation Report ──────────────────────────────────────────────────

export function generateRemediationReport(
  packages: Array<{ name: string; version: string; report: RiskReport }>
): RemediationReport {
  const remediations: PackageRemediation[] = [];

  for (const pkg of packages) {
    if (pkg.report.score < 1) continue;

    const suggestions = generateSuggestions(pkg.name, pkg.version, pkg.report);
    if (suggestions.length > 0) {
      remediations.push({
        packageName: pkg.name,
        version: pkg.version,
        riskScore: pkg.report.score,
        suggestions,
      });
    }
  }

  const allSuggestions = remediations.flatMap((r) => r.suggestions);
  const critical = allSuggestions.filter((s) => s.priority === 'critical').length;
  const high = allSuggestions.filter((s) => s.priority === 'high').length;
  const medium = allSuggestions.filter((s) => s.priority === 'medium').length;
  const low = allSuggestions.filter((s) => s.priority === 'low').length;

  const effortHours = allSuggestions.reduce((sum, s) => {
    const hours = { trivial: 0.25, low: 1, medium: 4, high: 8 };
    return sum + hours[s.effort];
  }, 0);

  const estimatedEffort = effortHours < 1 ? '<1 hour'
    : effortHours < 8 ? `~${Math.round(effortHours)} hours`
      : `~${Math.round(effortHours / 8)} days`;

  return {
    packages: remediations.sort((a, b) => b.riskScore - a.riskScore),
    summary: { total: allSuggestions.length, critical, high, medium, low, estimatedEffort },
    timestamp: new Date().toISOString(),
  };
}

export function getAlternatives(packageName: string): AlternativePackage[] {
  return ALTERNATIVES[packageName] ?? [];
}
