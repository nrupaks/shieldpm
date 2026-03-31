/**
 * ShieldPM — Community-Maintained Allowlist
 *
 * Trusted packages that are known-safe despite having high-risk patterns.
 * These packages legitimately need filesystem, network, or process access.
 *
 * Contributing: Add packages with justification. Each entry explains WHY
 * the package triggers alerts and WHY it's safe.
 */

export interface AllowlistEntry {
  /** npm package name */
  name: string;
  /** Why this package triggers alerts */
  reason: string;
  /** Maximum allowed risk score (findings above this still flag) */
  maxAllowedScore: number;
  /** Categories of findings to suppress */
  suppressCategories: string[];
  /** URL for verification */
  repository: string;
  /** Weekly npm downloads (approximate, for trust signal) */
  weeklyDownloads: string;
  /** Last verified date */
  verified: string;
}

/**
 * Packages verified as safe despite triggering static analysis alerts.
 * Organized by category.
 */
export const ALLOWLIST: AllowlistEntry[] = [
  // ─── Build Tools & Compilers ────────────────────────────────
  {
    name: 'typescript',
    reason: 'Compiler — legitimately reads/writes files, spawns processes for compilation',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'code-execution'],
    repository: 'https://github.com/microsoft/TypeScript',
    weeklyDownloads: '50M+',
    verified: '2026-03',
  },
  {
    name: 'eslint',
    reason: 'Linter — reads source files, loads plugins dynamically, accesses filesystem',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'code-execution', 'process'],
    repository: 'https://github.com/eslint/eslint',
    weeklyDownloads: '40M+',
    verified: '2026-03',
  },
  {
    name: 'tailwindcss',
    reason: 'CSS framework — scans source files for class usage, writes output CSS',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process'],
    repository: 'https://github.com/tailwindlabs/tailwindcss',
    weeklyDownloads: '15M+',
    verified: '2026-03',
  },
  {
    name: 'postcss',
    reason: 'CSS processor — reads/transforms CSS files, loads plugins',
    maxAllowedScore: 8,
    suppressCategories: ['filesystem', 'code-execution'],
    repository: 'https://github.com/postcss/postcss',
    weeklyDownloads: '40M+',
    verified: '2026-03',
  },
  {
    name: 'tsx',
    reason: 'TypeScript executor — compiles and runs TS files, spawns node processes',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'code-execution'],
    repository: 'https://github.com/privatenumber/tsx',
    weeklyDownloads: '5M+',
    verified: '2026-03',
  },
  {
    name: 'esbuild',
    reason: 'Bundler — reads source files, writes bundles, uses native binaries',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'code-execution', 'network'],
    repository: 'https://github.com/evanw/esbuild',
    weeklyDownloads: '25M+',
    verified: '2026-03',
  },
  {
    name: 'webpack',
    reason: 'Bundler — full filesystem access, dynamic requires, process spawning',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'code-execution'],
    repository: 'https://github.com/webpack/webpack',
    weeklyDownloads: '25M+',
    verified: '2026-03',
  },
  {
    name: 'vite',
    reason: 'Build tool — dev server with network access, file watching, HMR',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'network', 'code-execution'],
    repository: 'https://github.com/vitejs/vite',
    weeklyDownloads: '15M+',
    verified: '2026-03',
  },

  // ─── Frameworks & Runtimes ──────────────────────────────────
  {
    name: 'next',
    reason: 'Full-stack framework — server rendering, API routes, file-based routing',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'network', 'code-execution'],
    repository: 'https://github.com/vercel/next.js',
    weeklyDownloads: '10M+',
    verified: '2026-03',
  },
  {
    name: 'react',
    reason: 'UI library — uses eval-like patterns for JSX transform in dev mode',
    maxAllowedScore: 6,
    suppressCategories: ['code-execution'],
    repository: 'https://github.com/facebook/react',
    weeklyDownloads: '25M+',
    verified: '2026-03',
  },
  {
    name: 'react-dom',
    reason: 'DOM renderer — innerHTML usage for hydration, process.env checks',
    maxAllowedScore: 10,
    suppressCategories: ['code-execution', 'environment'],
    repository: 'https://github.com/facebook/react',
    weeklyDownloads: '25M+',
    verified: '2026-03',
  },
  {
    name: 'express',
    reason: 'Web framework — network listener, request parsing, middleware chain',
    maxAllowedScore: 8,
    suppressCategories: ['network', 'code-execution'],
    repository: 'https://github.com/expressjs/express',
    weeklyDownloads: '30M+',
    verified: '2026-03',
  },

  // ─── Database & ORM ─────────────────────────────────────────
  {
    name: 'prisma',
    reason: 'ORM — generates client code, reads schema files, spawns query engine binary',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'code-execution', 'network'],
    repository: 'https://github.com/prisma/prisma',
    weeklyDownloads: '3M+',
    verified: '2026-03',
  },
  {
    name: '@prisma/client',
    reason: 'Generated DB client — connects to databases, reads env for connection strings',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'network', 'environment', 'code-execution'],
    repository: 'https://github.com/prisma/prisma',
    weeklyDownloads: '3M+',
    verified: '2026-03',
  },

  // ─── API & SDK ──────────────────────────────────────────────
  {
    name: '@anthropic-ai/sdk',
    reason: 'AI SDK — makes HTTPS calls to Anthropic API, reads API key from env',
    maxAllowedScore: 10,
    suppressCategories: ['network', 'environment'],
    repository: 'https://github.com/anthropics/anthropic-sdk-node',
    weeklyDownloads: '500K+',
    verified: '2026-03',
  },
  {
    name: 'openai',
    reason: 'AI SDK — makes HTTPS calls to OpenAI API, reads API key from env',
    maxAllowedScore: 10,
    suppressCategories: ['network', 'environment'],
    repository: 'https://github.com/openai/openai-node',
    weeklyDownloads: '2M+',
    verified: '2026-03',
  },
  {
    name: 'axios',
    reason: 'HTTP client — network requests are its core purpose',
    maxAllowedScore: 8,
    suppressCategories: ['network'],
    repository: 'https://github.com/axios/axios',
    weeklyDownloads: '45M+',
    verified: '2026-03',
  },
  {
    name: 'node-fetch',
    reason: 'Fetch polyfill — network requests are its core purpose',
    maxAllowedScore: 8,
    suppressCategories: ['network'],
    repository: 'https://github.com/node-fetch/node-fetch',
    weeklyDownloads: '35M+',
    verified: '2026-03',
  },

  // ─── Auth & Security ────────────────────────────────────────
  {
    name: '@clerk/nextjs',
    reason: 'Auth SDK — reads env for API keys, makes auth API calls, sets cookies',
    maxAllowedScore: 8,
    suppressCategories: ['network', 'environment'],
    repository: 'https://github.com/clerk/javascript',
    weeklyDownloads: '500K+',
    verified: '2026-03',
  },
  {
    name: 'jsonwebtoken',
    reason: 'JWT library — crypto operations, Buffer usage for token encoding',
    maxAllowedScore: 6,
    suppressCategories: ['code-execution'],
    repository: 'https://github.com/auth0/node-jsonwebtoken',
    weeklyDownloads: '15M+',
    verified: '2026-03',
  },
  {
    name: 'bcrypt',
    reason: 'Password hashing — native C++ addon, crypto operations',
    maxAllowedScore: 6,
    suppressCategories: ['process'],
    repository: 'https://github.com/kelektiv/node.bcrypt.js',
    weeklyDownloads: '3M+',
    verified: '2026-03',
  },

  // ─── Utilities ──────────────────────────────────────────────
  {
    name: 'lodash',
    reason: 'Utility library — pure functions, no side effects',
    maxAllowedScore: 2,
    suppressCategories: [],
    repository: 'https://github.com/lodash/lodash',
    weeklyDownloads: '50M+',
    verified: '2026-03',
  },
  {
    name: 'framer-motion',
    reason: 'Animation library — DOM manipulation only, no system access',
    maxAllowedScore: 2,
    suppressCategories: [],
    repository: 'https://github.com/framer/motion',
    weeklyDownloads: '5M+',
    verified: '2026-03',
  },
  {
    name: 'lucide-react',
    reason: 'Icon library — pure SVG components, no side effects',
    maxAllowedScore: 1,
    suppressCategories: [],
    repository: 'https://github.com/lucide-icons/lucide',
    weeklyDownloads: '3M+',
    verified: '2026-03',
  },

  // ─── Image & Media ─────────────────────────────────────────
  {
    name: 'sharp',
    reason: 'Image processing — native binary (libvips), filesystem I/O',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process'],
    repository: 'https://github.com/lovell/sharp',
    weeklyDownloads: '10M+',
    verified: '2026-03',
  },
  {
    name: 'html-to-image',
    reason: 'Screenshot library — DOM access, canvas rendering',
    maxAllowedScore: 10,
    suppressCategories: ['code-execution'],
    repository: 'https://github.com/nicolo-ribaudo/html-to-image',
    weeklyDownloads: '500K+',
    verified: '2026-03',
  },

  // ─── Visualization ─────────────────────────────────────────
  {
    name: '@nivo/core',
    reason: 'Chart library — pure rendering, no system access',
    maxAllowedScore: 2,
    suppressCategories: [],
    repository: 'https://github.com/plouc/nivo',
    weeklyDownloads: '500K+',
    verified: '2026-03',
  },
  {
    name: '@nivo/bar',
    reason: 'Chart component — pure rendering',
    maxAllowedScore: 2,
    suppressCategories: [],
    repository: 'https://github.com/plouc/nivo',
    weeklyDownloads: '300K+',
    verified: '2026-03',
  },
  {
    name: '@nivo/line',
    reason: 'Chart component — pure rendering',
    maxAllowedScore: 2,
    suppressCategories: [],
    repository: 'https://github.com/plouc/nivo',
    weeklyDownloads: '300K+',
    verified: '2026-03',
  },
  {
    name: '@nivo/pie',
    reason: 'Chart component — pure rendering',
    maxAllowedScore: 2,
    suppressCategories: [],
    repository: 'https://github.com/plouc/nivo',
    weeklyDownloads: '200K+',
    verified: '2026-03',
  },
  {
    name: 'd3',
    reason: 'Visualization library — DOM manipulation, math operations',
    maxAllowedScore: 4,
    suppressCategories: ['code-execution'],
    repository: 'https://github.com/d3/d3',
    weeklyDownloads: '5M+',
    verified: '2026-03',
  },

  // ─── Graph & Layout ─────────────────────────────────────────
  {
    name: '@xyflow/react',
    reason: 'Flow diagram library — DOM rendering, no system access',
    maxAllowedScore: 3,
    suppressCategories: [],
    repository: 'https://github.com/xyflow/xyflow',
    weeklyDownloads: '500K+',
    verified: '2026-03',
  },
  {
    name: 'elkjs',
    reason: 'Graph layout engine — heavy computation, WASM/JS compiled from Java',
    maxAllowedScore: 10,
    suppressCategories: ['code-execution'],
    repository: 'https://github.com/kieler/elkjs',
    weeklyDownloads: '500K+',
    verified: '2026-03',
  },

  // ─── Testing ────────────────────────────────────────────────
  {
    name: 'vitest',
    reason: 'Test runner — spawns processes, reads test files, dynamic imports',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'code-execution'],
    repository: 'https://github.com/vitest-dev/vitest',
    weeklyDownloads: '10M+',
    verified: '2026-03',
  },
  {
    name: 'jest',
    reason: 'Test runner — spawns workers, filesystem access, code transformation',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'code-execution'],
    repository: 'https://github.com/jestjs/jest',
    weeklyDownloads: '20M+',
    verified: '2026-03',
  },

  // ─── Node.js Types ──────────────────────────────────────────
  {
    name: '@types/node',
    reason: 'Type definitions — contains type signatures for all Node.js APIs including fs, net, child_process',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'network', 'code-execution'],
    repository: 'https://github.com/DefinitelyTyped/DefinitelyTyped',
    weeklyDownloads: '50M+',
    verified: '2026-03',
  },
  {
    name: '@types/react',
    reason: 'Type definitions — pure types, no runtime code',
    maxAllowedScore: 1,
    suppressCategories: [],
    repository: 'https://github.com/DefinitelyTyped/DefinitelyTyped',
    weeklyDownloads: '20M+',
    verified: '2026-03',
  },

  // ─── Process Managers ───────────────────────────────────────
  {
    name: 'pm2',
    reason: 'Process manager — spawns/monitors/restarts processes by design',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process', 'network', 'code-execution'],
    repository: 'https://github.com/Unitech/pm2',
    weeklyDownloads: '2M+',
    verified: '2026-03',
  },
  {
    name: 'nodemon',
    reason: 'File watcher — watches filesystem, restarts processes on changes',
    maxAllowedScore: 10,
    suppressCategories: ['filesystem', 'process'],
    repository: 'https://github.com/remy/nodemon',
    weeklyDownloads: '5M+',
    verified: '2026-03',
  },
];

/* ─── Lookup helpers ─────────────────────────────────────────── */

const allowlistMap = new Map(ALLOWLIST.map((e) => [e.name, e]));

/** Check if a package is in the allowlist */
export function isAllowlisted(packageName: string): boolean {
  return allowlistMap.has(packageName);
}

/** Get allowlist entry for a package */
export function getAllowlistEntry(packageName: string): AllowlistEntry | undefined {
  return allowlistMap.get(packageName);
}

/** Get all allowlisted package names */
export function getAllowlistedNames(): string[] {
  return ALLOWLIST.map((e) => e.name);
}

/**
 * Apply allowlist to a risk score.
 * If the package is allowlisted and the score is within the allowed range,
 * return 0. Otherwise return the original score.
 */
export function applyAllowlist(
  packageName: string,
  originalScore: number,
  findings: { category: string }[],
): { adjustedScore: number; suppressed: boolean; entry?: AllowlistEntry } {
  const entry = allowlistMap.get(packageName);
  if (!entry) return { adjustedScore: originalScore, suppressed: false };

  // Filter out suppressed categories
  const unsuppressedFindings = findings.filter(
    (f) => !entry.suppressCategories.includes(f.category),
  );

  // If all findings are in suppressed categories, score is 0
  if (unsuppressedFindings.length === 0) {
    return { adjustedScore: 0, suppressed: true, entry };
  }

  // If score is within allowed range, reduce it
  if (originalScore <= entry.maxAllowedScore) {
    return { adjustedScore: 0, suppressed: true, entry };
  }

  // Score exceeds what's expected — something unusual, flag it
  return { adjustedScore: originalScore, suppressed: false, entry };
}
