/**
 * ShieldPM — Logger with levels and colored output
 */

import { red, green, yellow, cyan, dim, bold, boldRed, boldGreen, boldYellow } from './colors.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

let currentLevel: LogLevel = 'info';

export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

export function getLogLevel(): LogLevel {
  return currentLevel;
}

function shouldLog(level: LogLevel): boolean {
  return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[currentLevel];
}

function timestamp(): string {
  return dim(new Date().toISOString().slice(11, 19));
}

export function debug(...args: unknown[]): void {
  if (!shouldLog('debug')) return;
  console.log(dim('[debug]'), timestamp(), ...args);
}

export function info(...args: unknown[]): void {
  if (!shouldLog('info')) return;
  console.log(cyan('i'), ...args);
}

export function warn(...args: unknown[]): void {
  if (!shouldLog('warn')) return;
  console.warn(boldYellow('!'), yellow('warn'), ...args);
}

export function error(...args: unknown[]): void {
  if (!shouldLog('error')) return;
  console.error(boldRed('x'), red('error'), ...args);
}

export function success(...args: unknown[]): void {
  if (!shouldLog('info')) return;
  console.log(boldGreen('\u2713'), green(args.map(String).join(' ')));
}

export function header(text: string): void {
  if (!shouldLog('info')) return;
  console.log();
  console.log(bold(cyan(`  ${text}`)));
  console.log(dim('  ' + '\u2500'.repeat(text.length + 2)));
}

export function table(rows: [string, string][]): void {
  if (!shouldLog('info')) return;
  const maxKey = Math.max(...rows.map(([k]) => k.length));
  for (const [key, value] of rows) {
    console.log(`  ${dim(key.padEnd(maxKey))}  ${value}`);
  }
}

export const log = {
  debug,
  info,
  warn,
  error,
  success,
  header,
  table,
  setLevel: setLogLevel,
  getLevel: getLogLevel,
};

export default log;
