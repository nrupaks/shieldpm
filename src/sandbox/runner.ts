/**
 * ShieldPM — Sandbox Runner
 * Executes commands (especially postinstall scripts) in a restricted environment
 * with network blocking, timeout enforcement, and output capture.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { platform } from 'node:os';

// ── Types ────────────────────────────────────────────────────────────────

export interface SandboxOptions {
  /** Working directory for the command */
  cwd?: string;
  /** Timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Block network access (default: true) */
  blockNetwork?: boolean;
  /** Block environment variables (default: true) */
  blockEnv?: boolean;
  /** Allowed environment variable names to pass through */
  allowedEnvVars?: string[];
  /** Maximum stdout/stderr size in bytes (default: 1MB) */
  maxOutputSize?: number;
  /** Enable verbose logging of sandbox decisions */
  verbose?: boolean;
}

export interface SandboxResult {
  /** Process exit code (null if killed) */
  exitCode: number | null;
  /** Captured stdout */
  stdout: string;
  /** Captured stderr */
  stderr: string;
  /** Warnings generated during execution */
  warnings: string[];
  /** Actions that were blocked */
  blocked: string[];
  /** Whether the process was killed due to timeout */
  timedOut: boolean;
  /** Duration in milliseconds */
  durationMs: number;
}

// ── Safe environment builder ─────────────────────────────────────────────

const SAFE_ENV_VARS = new Set([
  'PATH',
  'HOME',
  'USER',
  'SHELL',
  'LANG',
  'LC_ALL',
  'TERM',
  'TMPDIR',
  'TMP',
  'TEMP',
  'NODE_ENV',
  'NODE_PATH',
]);

const SENSITIVE_ENV_VARS = new Set([
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'NPM_TOKEN',
  'NPM_AUTH_TOKEN',
  'DOCKER_PASSWORD',
  'SSH_AUTH_SOCK',
  'GPG_TTY',
  'DATABASE_URL',
  'REDIS_URL',
  'API_KEY',
  'SECRET_KEY',
  'PRIVATE_KEY',
]);

function buildSandboxEnv(
  blockNetwork: boolean,
  blockEnv: boolean,
  allowedEnvVars: string[]
): Record<string, string> {
  const env: Record<string, string> = {};

  if (blockEnv) {
    // Only pass through safe variables
    const allowed = new Set([...SAFE_ENV_VARS, ...allowedEnvVars]);
    for (const key of allowed) {
      if (process.env[key] !== undefined) {
        env[key] = process.env[key]!;
      }
    }
  } else {
    // Pass through everything except sensitive vars
    for (const [key, value] of Object.entries(process.env)) {
      if (!SENSITIVE_ENV_VARS.has(key) && value !== undefined) {
        env[key] = value;
      }
    }
    // Also pass explicitly allowed
    for (const key of allowedEnvVars) {
      if (process.env[key] !== undefined) {
        env[key] = process.env[key]!;
      }
    }
  }

  // Block network via proxy settings
  if (blockNetwork) {
    env['HTTP_PROXY'] = 'http://blocked.shieldpm.local:0';
    env['HTTPS_PROXY'] = 'http://blocked.shieldpm.local:0';
    env['http_proxy'] = 'http://blocked.shieldpm.local:0';
    env['https_proxy'] = 'http://blocked.shieldpm.local:0';
    env['no_proxy'] = '';
    env['NODE_OPTIONS'] = [
      env['NODE_OPTIONS'] ?? '',
      '--dns-result-order=verbatim',
    ].filter(Boolean).join(' ');
  }

  // Prevent spawning of sub-shells from modifying real config
  env['npm_config_ignore_scripts'] = 'true';

  return env;
}

// ── Platform-specific restrictions ───────────────────────────────────────

function buildPlatformArgs(): string[] {
  const args: string[] = [];

  if (platform() === 'linux') {
    // On Linux, we could use unshare for network namespace isolation
    // For now, we rely on proxy blocking; future: seccomp/landlock
  }

  return args;
}

// ── Output truncation ────────────────────────────────────────────────────

function truncateOutput(output: string, maxSize: number): string {
  if (Buffer.byteLength(output) <= maxSize) return output;

  const truncated = output.slice(0, maxSize);
  return truncated + `\n... [output truncated at ${Math.round(maxSize / 1024)}KB]`;
}

// ── Main runner ──────────────────────────────────────────────────────────

/**
 * Run a command inside a restricted sandbox environment.
 */
export async function runSandboxed(
  command: string,
  args: string[] = [],
  options: SandboxOptions = {}
): Promise<SandboxResult> {
  const {
    cwd = process.cwd(),
    timeout = 30_000,
    blockNetwork = true,
    blockEnv = true,
    allowedEnvVars = [],
    maxOutputSize = 1024 * 1024, // 1MB
    verbose = false,
  } = options;

  const warnings: string[] = [];
  const blocked: string[] = [];

  // Build restricted environment
  const env = buildSandboxEnv(blockNetwork, blockEnv, allowedEnvVars);

  if (blockNetwork) {
    blocked.push('network: HTTP/HTTPS proxied to blocked endpoint');
  }
  if (blockEnv) {
    const removedCount = Object.keys(process.env).length - Object.keys(env).length;
    blocked.push(`environment: ${removedCount} env vars stripped`);
  }

  const startTime = Date.now();
  let timedOut = false;

  return new Promise<SandboxResult>((resolve) => {
    let child: ChildProcess;
    let stdoutChunks: Buffer[] = [];
    let stderrChunks: Buffer[] = [];
    let stdoutSize = 0;
    let stderrSize = 0;

    try {
      child = spawn(command, args, {
        cwd,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: true,
        // Kill the entire process group on timeout
        detached: false,
      });
    } catch (err) {
      resolve({
        exitCode: 1,
        stdout: '',
        stderr: `Failed to spawn process: ${err instanceof Error ? err.message : String(err)}`,
        warnings,
        blocked,
        timedOut: false,
        durationMs: Date.now() - startTime,
      });
      return;
    }

    // Capture stdout
    child.stdout?.on('data', (chunk: Buffer) => {
      if (stdoutSize < maxOutputSize) {
        stdoutChunks.push(chunk);
        stdoutSize += chunk.length;
      }
    });

    // Capture stderr
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderrSize < maxOutputSize) {
        stderrChunks.push(chunk);
        stderrSize += chunk.length;
      }

      // Watch for suspicious patterns in stderr
      const text = chunk.toString();
      if (/ECONNREFUSED|ENOTFOUND|blocked\.shieldpm/.test(text)) {
        warnings.push('Process attempted network access (blocked by sandbox)');
      }
    });

    // Timeout
    const timer = setTimeout(() => {
      timedOut = true;
      warnings.push(`Process killed: exceeded ${timeout}ms timeout`);
      child.kill('SIGKILL');
    }, timeout);

    // Completion
    child.on('close', (code) => {
      clearTimeout(timer);

      const stdout = truncateOutput(Buffer.concat(stdoutChunks).toString('utf-8'), maxOutputSize);
      const stderr = truncateOutput(Buffer.concat(stderrChunks).toString('utf-8'), maxOutputSize);

      if (code !== 0 && !timedOut) {
        warnings.push(`Process exited with code ${code}`);
      }

      resolve({
        exitCode: code,
        stdout,
        stderr,
        warnings,
        blocked,
        timedOut,
        durationMs: Date.now() - startTime,
      });
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        exitCode: 1,
        stdout: Buffer.concat(stdoutChunks).toString('utf-8'),
        stderr: err.message,
        warnings: [...warnings, `Spawn error: ${err.message}`],
        blocked,
        timedOut: false,
        durationMs: Date.now() - startTime,
      });
    });

    // Close stdin immediately
    child.stdin?.end();
  });
}

/**
 * Run an npm postinstall script in the sandbox.
 */
export async function runPostInstall(
  packageDir: string,
  script: string,
  options: SandboxOptions = {}
): Promise<SandboxResult> {
  return runSandboxed('sh', ['-c', script], {
    cwd: packageDir,
    timeout: 30_000,
    blockNetwork: true,
    blockEnv: true,
    ...options,
  });
}
