```
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ██████╗ ███╗   ███╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔══██╗████╗ ████║
  ███████╗███████║██║█████╗  ██║     ██║  ██║██████╔╝██╔████╔██║
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██╔═══╝ ██║╚██╔╝██║
  ███████║██║  ██║██║███████╗███████╗██████╔╝██║     ██║ ╚═╝ ██║
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚═╝     ╚═╝     ╚═╝
```

# ShieldPM

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)
[![npm](https://img.shields.io/badge/npm-shieldpm-red.svg)](https://www.npmjs.com/package/shieldpm)

**Runtime-aware package firewall for Node.js** — sandbox, monitor, and enforce least-privilege on every npm dependency.

ShieldPM scans packages for malicious patterns, blocks typosquatting attempts, sandboxes install scripts, and enforces a permission manifest so your dependencies only access what you allow.

---

## Install

```bash
npm install -g shieldpm
```

Or use without installing:

```bash
npx shieldpm audit
```

## Quick Start

```bash
# Install a package with full protection (typosquat check + static analysis + sandbox)
shieldpm install axios

# Audit all current dependencies for risks
shieldpm audit

# Deep audit with per-finding detail
shieldpm audit --deep

# Inspect what a specific package actually does
shieldpm inspect lodash

# Run any command in a sandboxed environment (no network, stripped env)
shieldpm sandbox node scripts/postinstall.js

# Auto-generate a permission manifest from your dependencies
shieldpm manifest generate

# Show what changed in your dependency tree since last commit
shieldpm diff
```

## What It Does

### Static Analysis Engine
Scans every `.js`/`.ts` file in a package for:
- **Code execution**: `eval()`, `Function()`, `vm.runInContext()`
- **Process spawning**: `child_process`, `exec`, `spawn`
- **Network access**: `http.request`, `fetch()`, `dns.lookup`, `WebSocket`
- **File system access**: reads/writes to sensitive paths (`/etc/passwd`, `~/.ssh`, `~/.npmrc`)
- **Environment exfiltration**: `JSON.stringify(process.env)`
- **Obfuscation**: `String.fromCharCode`, hex escape sequences, base64 decode
- **Prototype pollution**: `__proto__` access, `constructor.prototype`
- **Install scripts**: `preinstall`/`postinstall` scripts

Each package gets a **risk score from 0-10** with detailed findings.

### Typosquatting Detection
Checks package names against the top npm packages using:
- Levenshtein distance (edit distance <= 2)
- Character transposition (`exprses` vs `express`)
- Hyphen/underscore/dot confusion (`lo-dash` vs `lodash`)
- Scope confusion (`@tyeps/react` vs `@types/react`)
- Repeated/missing characters (`expresss`, `expres`)

### Sandboxed Execution
Runs postinstall scripts and arbitrary commands in a restricted environment:
- **Network blocked** via proxy redirection
- **Environment stripped** (only PATH, HOME, NODE_ENV pass through)
- **Sensitive vars removed** (AWS keys, tokens, database URLs)
- **30-second timeout** with kill
- Full stdout/stderr capture

### Permission Manifest
Define exactly what each dependency is allowed to do in `shieldpm.json`:

```json
{
  "version": 1,
  "permissions": {
    "axios": { "net": ["*.api.example.com"], "fs": false },
    "lodash": { "net": false, "fs": false },
    "sharp": { "fs": ["./uploads", "./cache"], "net": false, "native": true }
  }
}
```

Auto-generate it with `shieldpm manifest generate`, then review and tighten.

### Behavioral Fingerprinting
Creates a cryptographic profile of each package:
- SHA-256 hash of all source files
- Complete import/require graph
- Network endpoints found in source
- File paths accessed
- Native module bindings

Compare profiles across versions to detect supply chain attacks.

### Dependency Diff
Compare your dependency tree before and after changes:
- New packages, removed packages, version bumps
- Flags: new install scripts, new native modules, major version bumps, version downgrades
- Works with `package-lock.json` via git history

## Feature Comparison

| Feature | ShieldPM | npm audit | Socket.dev |
|---------|----------|-----------|------------|
| Known vulnerability check | Planned | Yes | Yes |
| Static code analysis | Yes | No | Yes |
| Typosquatting detection | Yes | No | Yes |
| Sandboxed install scripts | Yes | No | No |
| Permission manifest | Yes | No | No |
| Behavioral fingerprinting | Yes | No | Partial |
| Dependency diff | Yes | No | Partial |
| Runtime enforcement | Yes | No | No |
| Free & open source | Yes | Yes | Freemium |
| Zero dependencies | Yes | N/A | N/A |

## Architecture

```
shieldpm
├── src/
│   ├── cli.ts                    # CLI entry point (process.argv parsing)
│   ├── index.ts                  # Public API exports
│   ├── analyzer/
│   │   ├── static.ts             # Pattern-based static analysis engine
│   │   └── typosquat.ts          # Typosquatting detection (Levenshtein + heuristics)
│   ├── sandbox/
│   │   └── runner.ts             # Restricted process execution
│   ├── monitor/
│   │   └── permissions.ts        # shieldpm.json manifest load/validate/generate
│   ├── fingerprint/
│   │   └── profile.ts            # Behavioral profiling and diff
│   ├── diff/
│   │   └── dependency.ts         # package-lock.json diff engine
│   └── utils/
│       ├── colors.ts             # ANSI terminal colors (zero deps)
│       └── logger.ts             # Leveled logger
├── package.json
├── tsconfig.json
└── shieldpm.json                 # (generated) permission manifest
```

## CLI Reference

```
shieldpm install <package>       Install with protection (typosquat + analysis + sandbox)
shieldpm audit                   Audit current dependencies
shieldpm audit --deep            Deep audit with per-finding detail
shieldpm inspect <package>       Show what a package does
shieldpm sandbox <command>       Run command in sandbox
shieldpm manifest generate       Auto-generate permission manifest
shieldpm manifest enforce        Validate manifest coverage
shieldpm diff                    Show dependency changes since last commit
shieldpm help                    Show help
shieldpm version                 Show version

Options:
  --verbose                      Enable debug logging
  --no-color                     Disable colored output
  --json                         Machine-readable output
  --force                        Bypass typosquatting blocks
```

## Permission Manifest Reference

The `shieldpm.json` file controls what each dependency is allowed to do:

```json
{
  "version": 1,
  "permissions": {
    "<package-name>": {
      "net": ["<glob-pattern>"] | false,
      "fs": ["<path>"] | false,
      "native": true | false,
      "exec": true | false,
      "env": ["<VAR_NAME>"] | true | false
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `net` | `string[] \| false` | Allowed network destinations (glob). `false` = no network. |
| `fs` | `string[] \| false` | Allowed filesystem paths. `false` = no fs access. |
| `native` | `boolean` | Whether native C++ addons are allowed. |
| `exec` | `boolean` | Whether `child_process` is allowed. |
| `env` | `string[] \| boolean` | Allowed env vars, `true` = all, `false` = none. |

## Contributing

Contributions are welcome! This is a free, open-source project.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `npm test`
5. Build: `npm run build`
6. Submit a pull request

### Development

```bash
git clone https://github.com/nrupaks/shieldpm.git
cd shieldpm
npm install
npm run dev -- help       # Run CLI in development mode
npm run build             # Compile TypeScript
npm test                  # Run tests
```

## Built with Claude

This project was built with [Claude](https://claude.ai) by Anthropic.

## License

[MIT](LICENSE) - Nrupak Shah
