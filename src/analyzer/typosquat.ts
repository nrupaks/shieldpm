/**
 * ShieldPM — Typosquatting Detector
 * Checks package names against popular npm packages to detect
 * typosquatting attempts using multiple heuristics.
 */

// ── Top 50 popular npm packages ──────────────────────────────────────────

export const POPULAR_PACKAGES: string[] = [
  'express', 'lodash', 'react', 'axios', 'chalk', 'commander', 'moment',
  'debug', 'uuid', 'dotenv', 'typescript', 'webpack', 'eslint', 'prettier',
  'jest', 'mocha', 'bluebird', 'underscore', 'async', 'request', 'yargs',
  'inquirer', 'glob', 'minimist', 'semver', 'mkdirp', 'rimraf', 'cheerio',
  'socket.io', 'mongoose', 'sequelize', 'passport', 'nodemon', 'pm2',
  'next', 'nuxt', 'vue', 'angular', 'svelte', 'fastify', 'koa', 'hapi',
  'body-parser', 'cors', 'helmet', 'jsonwebtoken', 'bcrypt', 'sharp',
  'puppeteer', 'redis',
];

// ── Types ────────────────────────────────────────────────────────────────

export type DetectionMethod =
  | 'levenshtein'
  | 'character-swap'
  | 'hyphen-underscore'
  | 'scope-confusion'
  | 'repeated-character'
  | 'missing-character'
  | 'extra-character';

export interface TyposquatResult {
  /** Whether the package name is suspicious */
  isSuspicious: boolean;
  /** The popular package it resembles */
  similarTo: string;
  /** Edit distance or similarity metric */
  distance: number;
  /** How the similarity was detected */
  method: DetectionMethod;
  /** Human-readable explanation */
  reason: string;
}

// ── Levenshtein distance ─────────────────────────────────────────────────

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  if (m === 0) return n;
  if (n === 0) return m;

  // Use two rows instead of full matrix for memory efficiency
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);

  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,       // deletion
        curr[j - 1] + 1,   // insertion
        prev[j - 1] + cost  // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

// ── Detection functions ──────────────────────────────────────────────────

function normalizePackageName(name: string): { scope: string; base: string } {
  const match = name.match(/^(@[^/]+)\/(.+)$/);
  if (match) {
    return { scope: match[1], base: match[2] };
  }
  return { scope: '', base: name };
}

/**
 * Check for character swaps (transpositions) — e.g. "exprses" vs "express"
 */
function detectCharacterSwap(input: string, target: string): boolean {
  if (input.length !== target.length) return false;
  if (input === target) return false;

  let diffs = 0;
  const diffPositions: number[] = [];

  for (let i = 0; i < input.length; i++) {
    if (input[i] !== target[i]) {
      diffs++;
      diffPositions.push(i);
    }
  }

  // Exactly two adjacent characters swapped
  if (diffs === 2) {
    const [p1, p2] = diffPositions;
    return (
      p2 - p1 === 1 &&
      input[p1] === target[p2] &&
      input[p2] === target[p1]
    );
  }

  return false;
}

/**
 * Check for hyphen/underscore confusion — e.g. "lodash" vs "lo-dash", "lo_dash"
 */
function detectHyphenUnderscore(input: string, target: string): boolean {
  const normalize = (s: string) => s.replace(/[-_.]/g, '');
  return normalize(input) === normalize(target) && input !== target;
}

/**
 * Check for scope confusion — e.g. "@tyeps/react" vs "@types/react"
 */
function detectScopeConfusion(input: string, knownPackages: string[]): TyposquatResult | null {
  const { scope, base } = normalizePackageName(input);
  if (!scope) return null;

  // Common scope typos
  const knownScopes = ['@types', '@babel', '@angular', '@vue', '@react-native'];

  for (const known of knownScopes) {
    if (scope !== known && levenshtein(scope, known) <= 2) {
      const fullKnown = `${known}/${base}`;
      return {
        isSuspicious: true,
        similarTo: fullKnown,
        distance: levenshtein(scope, known),
        method: 'scope-confusion',
        reason: `Scope "${scope}" looks like a typo of "${known}"`,
      };
    }
  }

  return null;
}

/**
 * Check for repeated characters — e.g. "expresss" vs "express"
 */
function detectRepeatedChar(input: string, target: string): boolean {
  if (input.length !== target.length + 1) return false;

  // Try removing each character from input and see if it matches target
  for (let i = 0; i < input.length; i++) {
    const reduced = input.slice(0, i) + input.slice(i + 1);
    if (reduced === target) return true;
  }
  return false;
}

// ── Main detection ───────────────────────────────────────────────────────

/**
 * Check a package name for typosquatting against known popular packages.
 * Returns null if the name appears safe.
 */
export function checkTyposquatting(
  packageName: string,
  knownPackages: string[] = POPULAR_PACKAGES
): TyposquatResult | null {
  const { base: inputBase } = normalizePackageName(packageName);

  // Exact match — it's a real popular package, not suspicious
  if (knownPackages.includes(packageName) || knownPackages.includes(inputBase)) {
    return null;
  }

  // Check scope confusion first
  const scopeResult = detectScopeConfusion(packageName, knownPackages);
  if (scopeResult) return scopeResult;

  // Check against each known package
  let bestMatch: TyposquatResult | null = null;
  let bestDistance = Infinity;

  for (const known of knownPackages) {
    const { base: knownBase } = normalizePackageName(known);

    // Skip if the lengths are too different for meaningful comparison
    if (Math.abs(inputBase.length - knownBase.length) > 2) continue;

    // Hyphen/underscore confusion
    if (detectHyphenUnderscore(inputBase, knownBase)) {
      return {
        isSuspicious: true,
        similarTo: known,
        distance: 0,
        method: 'hyphen-underscore',
        reason: `"${packageName}" differs from "${known}" only by hyphen/underscore/dot`,
      };
    }

    // Character swap
    if (detectCharacterSwap(inputBase, knownBase)) {
      return {
        isSuspicious: true,
        similarTo: known,
        distance: 1,
        method: 'character-swap',
        reason: `"${packageName}" has swapped characters compared to "${known}"`,
      };
    }

    // Repeated character
    if (detectRepeatedChar(inputBase, knownBase)) {
      return {
        isSuspicious: true,
        similarTo: known,
        distance: 1,
        method: 'repeated-character',
        reason: `"${packageName}" has a repeated character compared to "${known}"`,
      };
    }

    // Missing character
    if (detectRepeatedChar(knownBase, inputBase)) {
      return {
        isSuspicious: true,
        similarTo: known,
        distance: 1,
        method: 'missing-character',
        reason: `"${packageName}" is missing a character compared to "${known}"`,
      };
    }

    // General Levenshtein distance
    const dist = levenshtein(inputBase, knownBase);
    if (dist <= 2 && dist < bestDistance) {
      bestDistance = dist;
      bestMatch = {
        isSuspicious: true,
        similarTo: known,
        distance: dist,
        method: 'levenshtein',
        reason: `"${packageName}" is ${dist} edit(s) away from "${known}"`,
      };
    }
  }

  return bestMatch;
}

/**
 * Batch-check multiple package names.
 */
export function checkMultiple(
  packageNames: string[],
  knownPackages: string[] = POPULAR_PACKAGES
): Map<string, TyposquatResult> {
  const results = new Map<string, TyposquatResult>();

  for (const name of packageNames) {
    const result = checkTyposquatting(name, knownPackages);
    if (result) {
      results.set(name, result);
    }
  }

  return results;
}
