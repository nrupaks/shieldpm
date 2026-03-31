```
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ██████╗ ███╗   ███╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔══██╗████╗ ████║
  ███████╗███████║██║█████╗  ██║     ██║  ██║██████╔╝██╔████╔██║
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██╔═══╝ ██║╚██╔╝██║
  ███████║██║  ██║██║███████╗███████╗██████╔╝██║     ██║ ╚═╝ ██║
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚═╝     ╚═╝     ╚═╝
```

# ShieldPM v0.4.0

**Runtime-aware package firewall + OWASP source code scanner for Node.js**

Zero dependencies. 120+ security rules. OWASP Top 10 mapped. One command to scan.

---

## Why ShieldPM?

Every npm install is a trust decision. ShieldPM protects your project at **two levels**:

1. **Dependency Security** — Scans npm packages for malicious patterns, typosquatting, and supply chain attacks
2. **Source Code Security** — Scans your own code for OWASP Top 10 vulnerabilities, hardcoded secrets, and insecure patterns

Unlike `npm audit` (which only checks known CVEs), ShieldPM performs **behavioral analysis** — detecting what packages actually *do*, not just what's been reported.

## Quick Start

```bash
# Install globally
npm install -g shieldpm

# Scan your source code for vulnerabilities
shieldpm scan

# Scan with fix suggestions
shieldpm scan --fix

# Show OWASP Top 10 coverage report
shieldpm scan --owasp-report

# Audit npm dependencies
shieldpm audit --deep

# Generate full HTML security report
shieldpm report

# Generate SBOM (CycloneDX or SPDX)
shieldpm sbom --format=cyclonedx --output=sbom.json
```

## Features

### Source Code Scanner (NEW in v0.4.0)
| Feature | Description |
|---------|-------------|
| **120+ Security Rules** | Pattern-based detection across all OWASP Top 10 categories |
| **OWASP Top 10 2021 Mapping** | Every rule mapped to an OWASP category |
| **CWE ID Mapping** | Every rule mapped to a CWE identifier |
| **Fix Suggestions** | Actionable remediation for every finding |
| **False Positive Guidance** | When each rule may not apply |
| **Confidence Levels** | High/medium/low confidence per finding |
| **Secrets Detection** | AWS keys, GitHub tokens, Stripe keys, database URLs, private keys |
| **Framework-Specific Rules** | React, Next.js, TypeScript, Node.js patterns |
| **OWASP Coverage Report** | Shows coverage per category with compliance score |
| **CWE Coverage Matrix** | All CWEs covered with rule counts |
| **.shieldpmignore** | Exclude files/directories from scanning |

### Dependency Security
| Feature | Description |
|---------|-------------|
| **Static Analysis** | 30+ patterns for malicious behavior in dependencies |
| **Typosquatting Detection** | Catches misspelled package names |
| **Sandboxed Install Scripts** | Runs postinstall in restricted environment |
| **Permission Manifest** | Per-package least-privilege access control |
| **Behavioral Fingerprinting** | SHA-256 profiles to detect supply chain changes |
| **Dependency Diff** | Red flags on lockfile changes |

### Enterprise Features (v0.3.0+)
| Feature | Description |
|---------|-------------|
| **SBOM Generation** | CycloneDX 1.5 and SPDX 2.3 formats |
| **License Compliance** | Detect, classify, and enforce license policies |
| **Policy-as-Code** | Declarative security rules in JSON |
| **Allow/Deny Lists** | Centralized package governance |
| **Compliance Reporting** | SOC2, ISO 27001, PCI-DSS, EO 14028 controls |
| **CI/CD Integration** | GitHub Actions, GitLab CI, Azure DevOps generators |
| **Pre-commit Hook** | Auto-scan on dependency changes |
| **PR Decoration** | Markdown security reports for pull requests |
| **Break-the-Build Gate** | Configurable CI/CD pass/fail thresholds |
| **Provenance Verification** | npm provenance and Sigstore checks |
| **Maintainer Risk Scoring** | Bus factor and trust signal analysis |
| **Patch Suggestions** | Alternative packages and remediation actions |
| **Continuous Monitoring** | Lockfile drift and risk score tracking |
| **Security Posture Trending** | Track improvement over time |
| **HTML Report** | Beautiful tabbed report covering all modules |

## Architecture

```
shieldpm/src/
├── cli.ts                    CLI entry point (30+ commands)
├── index.ts                  Public API exports
├── scanner/                  Source Code Scanner (NEW)
│   ├── patterns.ts           120+ OWASP-mapped rules
│   ├── engine.ts             Scan engine with dedup & summary
│   └── owasp-report.ts       Coverage report & compliance scoring
├── analyzer/
│   ├── static.ts             Dependency static analysis (30+ rules)
│   └── typosquat.ts          Package name similarity detection
├── sandbox/
│   └── runner.ts             Sandboxed command execution
├── monitor/
│   └── permissions.ts        Permission manifest system
├── fingerprint/
│   └── profile.ts            Behavioral fingerprinting
├── diff/
│   └── dependency.ts         Lockfile diffing
├── allowlist/
│   └── index.ts              Community-maintained safe list
├── sbom/
│   └── generator.ts          CycloneDX & SPDX SBOM generation
├── license/
│   └── compliance.ts         License detection & policy enforcement
├── policy/
│   └── engine.ts             Policy-as-code rule engine
├── gateway/
│   └── lists.ts              Allow/deny package management
├── compliance/
│   └── reporter.ts           SOC2, ISO 27001, PCI-DSS, EO 14028
├── cicd/
│   └── integration.ts        CI/CD, pre-commit, PR decoration, gate
├── provenance/
│   └── verifier.ts           Package provenance verification
├── maintainer/
│   └── risk.ts               Maintainer trust scoring
├── remediation/
│   └── patches.ts            Patch suggestions & alternatives
├── monitoring/
│   └── watcher.ts            Continuous dependency monitoring
├── posture/
│   └── trending.ts           Security posture snapshots & trends
├── report/
│   └── html.ts               Interactive HTML report generator
└── utils/
    ├── colors.ts             Terminal colors (zero-dep)
    └── logger.ts             Leveled logging
```

**Zero production dependencies.** Built with Node.js core modules only.

## Configuration Files

| File | Purpose | Command to Create |
|------|---------|-------------------|
| `shieldpm.json` | Permission manifest (per-package access rules) | `shieldpm manifest generate` |
| `shieldpm-policy.json` | Security policy (declarative rules) | `shieldpm policy init` |
| `shieldpm-lists.json` | Package allow/deny lists | `shieldpm lists allow <pkg>` |
| `.shieldpmignore` | Exclude files/dirs from source scan | Create manually (gitignore syntax) |

## Programmatic API

```typescript
import {
  // Source code scanning
  scanProject, generateOWASPReport, ALL_RULES,
  // Dependency analysis
  analyzePackage, checkTyposquatting, runSandboxed,
  // SBOM & compliance
  generateSBOM, scanLicenses, generateComplianceReport,
  // Policy & governance
  evaluatePolicy, checkPackage, evaluateGate,
} from 'shieldpm';

// Scan project source code
const report = await scanProject({ dir: './src' });
console.log(`Found ${report.summary.totalFindings} issues`);

// Generate OWASP coverage report
const owasp = generateOWASPReport(report);
console.log(`OWASP compliance: ${owasp.overallScore}/100`);

// Analyze a dependency
const risk = await analyzePackage('./node_modules/some-package');
console.log(`Risk score: ${risk.score}/10`);
```

## What Does ShieldPM Scan For?

See [SCAN-COVERAGE.md](./SCAN-COVERAGE.md) for the complete list of 120+ rules with OWASP mapping, CWE IDs, and code examples.

**OWASP Top 10 Coverage Summary:**
- **A01 Broken Access Control** — Path traversal, CORS, IDOR, privilege escalation, JWT issues
- **A02 Cryptographic Failures** — Weak hashes, hardcoded keys, insecure ciphers, TLS bypass
- **A03 Injection** — SQL, NoSQL, command, LDAP, XPath, header, log, eval, template injection
- **A04 Insecure Design** — Race conditions, missing rate limiting, hardcoded credentials
- **A05 Security Misconfiguration** — Debug mode, verbose errors, exposed env files, stack traces
- **A06 Vulnerable Components** — Known compromised packages, deprecated APIs, wildcard versions
- **A07 Authentication Failures** — Hardcoded passwords, weak policy, session fixation, JWT attacks
- **A08 Software Integrity** — Eval from network, CDN without SRI, prototype pollution
- **A09 Logging Failures** — Sensitive data in logs, empty catches, missing audit trails
- **A10 SSRF** — Fetch/axios/http with user URLs, DNS rebinding, internal IP access

**Plus:** TypeScript patterns, React/Next.js XSS, Node.js API security, secrets detection, dependency confusion

## Full Command Reference

See [COMMANDS.md](./COMMANDS.md) for all 30+ commands with examples and flags.

## CI/CD Integration

```bash
# Generate GitHub Actions workflow
shieldpm cicd setup github-actions

# Install pre-commit hook
shieldpm hook install

# Run as CI gate (exits non-zero on failure)
shieldpm gate --max-risk-score=7 --max-critical=0
shieldpm scan --severity=high
```

## License

MIT — Nrupak Shah

## Links

- [Full Command Reference](./COMMANDS.md)
- [Scan Coverage & OWASP Mapping](./SCAN-COVERAGE.md)
- [GitHub](https://github.com/nrupaks/shieldpm)
