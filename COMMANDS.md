# ShieldPM CLI Command Reference

## Global Options

| Flag | Description |
|------|-------------|
| `--verbose` | Enable debug logging |
| `--no-color` | Disable colored output |
| `--json` | Output results as JSON |

---

## Source Code Scanning

### `shieldpm scan`
Scan project source code for security vulnerabilities using 120+ OWASP-mapped rules.

```bash
# Basic scan (current directory)
shieldpm scan

# Scan specific directory
shieldpm scan --dir=./src

# Show fix suggestions for each finding
shieldpm scan --fix

# Filter by severity (only show high and critical)
shieldpm scan --severity=high

# Filter by confidence (only high-confidence findings)
shieldpm scan --confidence=high

# JSON output for CI/CD
shieldpm scan --json

# Combine flags
shieldpm scan --dir=./src --severity=high --fix --json
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--dir=<path>` | `.` | Directory to scan |
| `--severity=<level>` | `low` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `--confidence=<level>` | `low` | Minimum confidence: `high`, `medium`, `low` |
| `--fix` | off | Show inline fix suggestions and false positive guidance |
| `--json` | off | Output full report as JSON |
| `--owasp-report` | off | Show OWASP Top 10 coverage report instead of scan |

**Exit codes:**
| Code | Meaning |
|------|---------|
| `0` | No critical findings |
| `1` | One or more critical findings detected |

### `shieldpm scan --owasp-report`
Show OWASP Top 10 coverage analysis with compliance scoring.

```bash
# Coverage report only (no scan)
shieldpm scan --owasp-report

# Coverage + scan results
shieldpm scan --owasp-report --dir=./src

# JSON format
shieldpm scan --owasp-report --json
```

**Output includes:**
- Total rules and unique CWEs
- Per-category coverage level (comprehensive/good/basic/minimal)
- Rule count and CWE count per category
- Compliance score (0-100)
- Gaps and recommendations

---

## Dependency Security

### `shieldpm install <package>`
Install a package with full security checks.

```bash
shieldpm install express
shieldpm install lodash --force  # bypass typosquatting warning
```

**Steps performed:**
1. Typosquatting check against 50+ popular packages
2. npm install with `--ignore-scripts`
3. Static analysis (30+ patterns)
4. Behavioral profile generation
5. Postinstall script sandboxing (if present)

### `shieldpm audit`
Audit all installed dependencies.

```bash
shieldpm audit           # Quick scan
shieldpm audit --deep    # Detailed analysis with findings
shieldpm audit --json    # Machine-readable output
```

### `shieldpm inspect <package>`
Deep analysis of a single package.

```bash
shieldpm inspect axios
shieldpm inspect ./node_modules/lodash
```

### `shieldpm sandbox <command>`
Run a command in a restricted sandbox.

```bash
shieldpm sandbox "node script.js"
shieldpm sandbox "npm run build"
```

**Sandbox restrictions:** Network blocked, env vars stripped, 30s timeout.

### `shieldpm diff`
Show dependency changes since last commit.

```bash
shieldpm diff
```

**Detects:** New packages, removed packages, version changes, new install scripts, native modules, major bumps, downgrades.

---

## SBOM & License

### `shieldpm sbom`
Generate Software Bill of Materials.

```bash
shieldpm sbom                              # CycloneDX to stdout
shieldpm sbom --format=spdx               # SPDX format
shieldpm sbom --output=sbom.json           # Save to file
shieldpm sbom --format=cyclonedx --output=sbom.json
```

### `shieldpm license scan`
Scan all dependency licenses.

```bash
shieldpm license scan
```

### `shieldpm license check`
Check licenses against compliance policy.

```bash
shieldpm license check
```

**Default policy:** Blocks AGPL-3.0 and SSPL-1.0. Warns on copyleft. Requires license declaration.

---

## Policy & Governance

### `shieldpm policy init`
Create a security policy file (`shieldpm-policy.json`).

```bash
shieldpm policy init
```

### `shieldpm policy check`
Evaluate all dependencies against security policy.

```bash
shieldpm policy check
```

### `shieldpm lists show`
Display allow/deny package lists.

```bash
shieldpm lists show
```

### `shieldpm lists allow <package> [reason]`
Add a package to the allowlist.

```bash
shieldpm lists allow lodash "Approved by security team"
```

### `shieldpm lists deny <package> [reason]`
Add a package to the denylist.

```bash
shieldpm lists deny event-stream "Known supply chain compromise"
```

### `shieldpm lists remove <package>`
Remove a package from all lists.

```bash
shieldpm lists remove lodash
```

---

## Compliance & Reporting

### `shieldpm compliance`
Generate compliance reports for multiple frameworks.

```bash
shieldpm compliance
```

**Frameworks:** SOC2 Type II, ISO/IEC 27001:2022, PCI DSS v4.0, Executive Order 14028.

### `shieldpm report`
Generate a full interactive HTML security report.

```bash
shieldpm report
shieldpm report --output=security-report.html
```

**Report tabs:** Overview, Risk Analysis, SBOM, Licenses, Compliance, Provenance, Maintainers, Remediation, Posture, Monitor.

---

## CI/CD Integration

### `shieldpm gate`
Run the security gate (pass/fail for CI/CD).

```bash
shieldpm gate
shieldpm gate --max-risk-score=7
shieldpm gate --max-critical=0 --max-high=5
```

**Exit code 1** on failure — blocks the build.

### `shieldpm cicd setup <provider>`
Generate CI/CD workflow configuration.

```bash
shieldpm cicd setup github-actions  # .github/workflows/shieldpm.yml
shieldpm cicd setup gitlab-ci       # .gitlab-ci-shieldpm.yml
shieldpm cicd setup azure-devops    # azure-pipelines-shieldpm.yml
```

### `shieldpm hook install`
Install a git pre-commit hook.

```bash
shieldpm hook install
```

### `shieldpm pr-comment`
Generate markdown for PR decoration.

```bash
shieldpm pr-comment
```

---

## Supply Chain Analysis

### `shieldpm provenance`
Verify package provenance and supply chain integrity.

```bash
shieldpm provenance
```

### `shieldpm maintainer`
Analyze maintainer risk scores for all dependencies.

```bash
shieldpm maintainer
```

### `shieldpm remediate`
Generate patch suggestions and alternative packages.

```bash
shieldpm remediate
```

---

## Monitoring & Posture

### `shieldpm manifest generate`
Auto-generate a permission manifest.

```bash
shieldpm manifest generate
```

### `shieldpm manifest enforce`
Validate all packages have manifest entries.

```bash
shieldpm manifest enforce
```

### `shieldpm monitor check`
Run a monitoring check for dependency changes.

```bash
shieldpm monitor check
```

### `shieldpm monitor status`
Show monitoring status and recent events.

```bash
shieldpm monitor status
```

### `shieldpm posture snapshot`
Take a security posture snapshot.

```bash
shieldpm posture snapshot
```

### `shieldpm posture trend`
Show security posture trend over time.

```bash
shieldpm posture trend
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success — all checks passed |
| `1` | Failure — critical findings, policy violations, or gate failures |

All commands that can block CI/CD (`scan`, `gate`, `policy check`, `license check`) use exit code 1 on failure.
