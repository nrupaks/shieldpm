# ShieldPM Scan Coverage — OWASP Top 10 Mapping

## Overview

ShieldPM includes **120+ security rules** mapped to the **OWASP Top 10 2021** framework. Each rule includes:
- OWASP category mapping
- CWE ID (Common Weakness Enumeration)
- Severity rating (critical/high/medium/low)
- Confidence level (high/medium/low)
- Actionable fix suggestion
- False positive guidance

Run `shieldpm scan --owasp-report` to see your coverage and compliance score.

---

## OWASP Top 10 Coverage Table

| OWASP Category | Rules | CWEs Covered | Coverage Level |
|----------------|-------|-------------|----------------|
| **A01:2021** Broken Access Control | 10 | CWE-22, 345, 548, 601, 639, 862, 942, 269 | Comprehensive |
| **A02:2021** Cryptographic Failures | 10 | CWE-256, 295, 326, 327, 338, 798 | Comprehensive |
| **A03:2021** Injection | 12 | CWE-78, 89, 90, 94, 95, 113, 117, 643, 943, 1333 | Comprehensive |
| **A04:2021** Insecure Design | 5 | CWE-20, 362, 770, 798, 1188 | Good |
| **A05:2021** Security Misconfiguration | 8 | CWE-209, 489, 538, 693, 942, 1393 | Comprehensive |
| **A06:2021** Vulnerable Components | 5 | CWE-327, 477, 829, 1035, 1104 | Good |
| **A07:2021** Auth Failures | 8 | CWE-259, 345, 384, 521, 598, 614, 836, 916 | Comprehensive |
| **A08:2021** Software Integrity | 6 | CWE-353, 494, 502, 829, 1321 | Good |
| **A09:2021** Logging Failures | 5 | CWE-209, 390, 532, 778 | Good |
| **A10:2021** SSRF | 6 | CWE-918 | Good |
| **EXTRA** TS/React/Node/Secrets/Deps | 28+ | CWE-22, 78, 79, 321, 427, 457, 476, 502, 601, 704, 710, 749, 798 | Comprehensive |

---

## Rules by OWASP Category

### A01:2021 — Broken Access Control

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A01-path-traversal` | CWE-22 | Critical | File operations with unsanitized user input |
| `A01-open-redirect` | CWE-601 | High | Redirect destination from user input |
| `A01-cors-wildcard` | CWE-942 | High | Access-Control-Allow-Origin: * |
| `A01-cors-reflect-origin` | CWE-942 | Critical | Echoing request Origin without validation |
| `A01-missing-auth-middleware` | CWE-862 | Medium | Sensitive routes without auth middleware |
| `A01-directory-listing` | CWE-548 | Medium | Static serving with dotfiles/directory listing |
| `A01-idor-direct-db` | CWE-639 | High | Database lookup using user-supplied ID without ownership check |
| `A01-privilege-escalation` | CWE-269 | Critical | Role/permission set from user input |
| `A01-insecure-object-ref` | CWE-639 | Medium | API routes with user resources needing auth |
| `A01-jwt-no-verify` | CWE-345 | Critical | jwt.decode() without verification |

### A02:2021 — Cryptographic Failures

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A02-md5-hash` | CWE-327 | High | createHash("md5") |
| `A02-sha1-hash` | CWE-327 | Medium | createHash("sha1") |
| `A02-hardcoded-secret` | CWE-798 | Critical | Cryptographic keys in source code |
| `A02-math-random-crypto` | CWE-338 | High | Math.random() in security context |
| `A02-cleartext-password-store` | CWE-256 | Critical | Password stored without hashing |
| `A02-weak-cipher` | CWE-327 | High | DES, RC4, RC2, ECB mode ciphers |
| `A02-ecb-mode` | CWE-327 | High | AES-ECB mode encryption |
| `A02-tls-reject-unauthorized` | CWE-295 | Critical | TLS certificate verification disabled |
| `A02-short-key-length` | CWE-326 | Medium | RSA key < 2048 bits |
| `A02-createCipher-deprecated` | CWE-327 | Medium | Deprecated crypto.createCipher() |

### A03:2021 — Injection

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A03-sql-concat` | CWE-89 | Critical | SQL built with string concatenation |
| `A03-sql-template-literal` | CWE-89 | Critical | SQL built with template literals |
| `A03-nosql-injection` | CWE-943 | Critical | NoSQL query with raw user input |
| `A03-command-injection-exec` | CWE-78 | Critical | exec/execSync with user input |
| `A03-command-injection-spawn` | CWE-78 | High | spawn/execFile with user input |
| `A03-ldap-injection` | CWE-90 | Critical | LDAP query with user input |
| `A03-xpath-injection` | CWE-643 | High | XPath with dynamic input |
| `A03-header-injection` | CWE-113 | High | HTTP header from user input |
| `A03-log-injection` | CWE-117 | Medium | Unsanitized input in logs |
| `A03-regex-dos` | CWE-1333 | Medium | Regex built from user input |
| `A03-eval-injection` | CWE-95 | Critical | eval() with user input |
| `A03-template-injection` | CWE-94 | Critical | User input as template source |

### A04:2021 — Insecure Design

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A04-race-condition` | CWE-362 | High | Read-then-write without transaction |
| `A04-missing-rate-limit` | CWE-770 | Medium | Auth endpoints without rate limiting |
| `A04-hardcoded-credentials` | CWE-798 | Critical | Username/password pairs in code |
| `A04-insecure-default` | CWE-1188 | Medium | Security features explicitly disabled |
| `A04-missing-input-validation` | CWE-20 | Medium | User input in sensitive ops without validation |

### A05:2021 — Security Misconfiguration

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A05-debug-enabled` | CWE-489 | Medium | Debug mode left on |
| `A05-verbose-error` | CWE-209 | Medium | Stack traces sent to client |
| `A05-default-credentials` | CWE-1393 | Critical | Common default passwords |
| `A05-missing-security-headers` | CWE-693 | Medium | Server without security headers |
| `A05-exposed-env-file` | CWE-538 | High | Static serving project root (exposes .env) |
| `A05-stack-trace-exposure` | CWE-209 | Medium | .stack in HTTP responses |
| `A05-dev-mode-production` | CWE-489 | Medium | Dev features in production |
| `A05-permissive-cors-credentials` | CWE-942 | High | credentials:true with wildcard origin |

### A06:2021 — Vulnerable & Outdated Components

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A06-known-vulnerable-import` | CWE-1035 | High | Imports of compromised packages |
| `A06-deprecated-api` | CWE-477 | Low | Deprecated Node.js APIs |
| `A06-wildcard-dependency` | CWE-1104 | Medium | "*" version in dependencies |
| `A06-outdated-crypto-lib` | CWE-327 | Medium | Third-party crypto vs built-in |
| `A06-git-dependency` | CWE-829 | Medium | git:// URL dependencies |

### A07:2021 — Identification & Authentication Failures

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A07-hardcoded-password` | CWE-259 | Critical | Passwords in source code |
| `A07-weak-password-policy` | CWE-521 | Medium | Minimum length < 8 |
| `A07-session-fixation` | CWE-384 | High | Session modified without regeneration |
| `A07-jwt-none-algorithm` | CWE-345 | Critical | JWT "none" algorithm allowed |
| `A07-insecure-cookie` | CWE-614 | Medium | Cookie without secure/httpOnly |
| `A07-credential-in-url` | CWE-598 | High | Passwords in URLs |
| `A07-plaintext-comparison` | CWE-836 | High | Timing-unsafe secret comparison |
| `A07-no-password-hash` | CWE-916 | Critical | Password storage without hashing |

### A08:2021 — Software & Data Integrity Failures

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A08-eval-from-network` | CWE-494 | Critical | eval() on network-fetched data |
| `A08-dynamic-require-url` | CWE-829 | Critical | require() from URL |
| `A08-cdn-no-sri` | CWE-353 | Medium | CDN scripts without SRI |
| `A08-prototype-pollution` | CWE-1321 | High | __proto__ / constructor.prototype access |
| `A08-unsafe-json-parse` | CWE-502 | Medium | JSON.parse on untrusted input |
| `A08-postinstall-exec` | CWE-829 | High | Install scripts executing code |

### A09:2021 — Security Logging & Monitoring Failures

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A09-sensitive-data-in-log` | CWE-532 | High | Passwords/tokens in log output |
| `A09-console-log-prod` | CWE-532 | Low | Debug logging of sensitive data |
| `A09-empty-catch` | CWE-390 | Medium | Empty catch blocks |
| `A09-missing-auth-logging` | CWE-778 | Medium | Auth functions without audit logging |
| `A09-error-info-leak` | CWE-209 | Medium | Error details in catch blocks sent to client |

### A10:2021 — Server-Side Request Forgery

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `A10-ssrf-fetch` | CWE-918 | Critical | fetch() with user-controlled URL |
| `A10-ssrf-axios` | CWE-918 | Critical | axios with user-controlled URL |
| `A10-ssrf-http-request` | CWE-918 | Critical | http.request with user-controlled URL |
| `A10-internal-ip-access` | CWE-918 | High | Hardcoded internal/metadata IPs |
| `A10-url-redirect-follow` | CWE-918 | Medium | Unlimited redirect following |
| `A10-dns-rebinding` | CWE-918 | High | DNS resolution with user input |

### EXTRA — Framework & Language Specific

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `TS-any-abuse` | CWE-704 | Low | TypeScript "any" type usage |
| `TS-ts-ignore` | CWE-710 | Low | @ts-ignore comments |
| `TS-non-null-assertion` | CWE-476 | Low | Non-null assertion (!) operator |
| `TS-as-any-cast` | CWE-704 | Medium | "as any" type casting |
| `REACT-dangerous-html` | CWE-79 | High | dangerouslySetInnerHTML |
| `REACT-href-javascript` | CWE-79 | Critical | javascript: protocol in href |
| `REACT-unescaped-user-output` | CWE-79 | Medium | URL params in JSX |
| `REACT-unsafe-lifecycle` | CWE-749 | Low | UNSAFE_ lifecycle methods |
| `REACT-open-redirect-router` | CWE-601 | High | Router navigation with user URL |
| `NODE-path-join-user` | CWE-22 | High | path.join with user input |
| `NODE-fs-user-path` | CWE-22 | High | fs operations with user path |
| `NODE-unsafe-deserialize` | CWE-502 | Critical | Deserialization of user data |
| `NODE-child-process-user` | CWE-78 | Critical | child_process with user input |
| `NODE-buffer-alloc-unsafe` | CWE-457 | Medium | Buffer.allocUnsafe() |

### EXTRA — Secrets Detection

| Rule ID | CWE | Severity | What It Detects |
|---------|-----|----------|-----------------|
| `SEC-aws-access-key` | CWE-798 | Critical | AWS Access Key IDs (AKIA...) |
| `SEC-github-token` | CWE-798 | Critical | GitHub PATs and tokens |
| `SEC-stripe-key` | CWE-798 | Critical | Stripe live secret keys |
| `SEC-generic-api-key` | CWE-798 | High | Generic API key assignments |
| `SEC-private-key-pem` | CWE-321 | Critical | PEM private keys |
| `SEC-jwt-secret-hardcoded` | CWE-798 | Critical | JWT signing secrets |
| `SEC-database-url` | CWE-798 | Critical | Database connection strings |
| `SEC-password-in-assignment` | CWE-798 | High | Passwords as string literals |

---

## CWE Coverage Matrix

ShieldPM covers **40+ unique CWEs**. The most critical ones:

| CWE | Name | Rules |
|-----|------|-------|
| CWE-22 | Path Traversal | 4 |
| CWE-78 | OS Command Injection | 4 |
| CWE-79 | Cross-site Scripting | 4 |
| CWE-89 | SQL Injection | 2 |
| CWE-327 | Broken Crypto Algorithm | 5 |
| CWE-502 | Unsafe Deserialization | 3 |
| CWE-798 | Hardcoded Credentials | 7 |
| CWE-918 | SSRF | 6 |
| CWE-942 | Permissive CORS | 4 |

---

## False Positive Guidance

Every rule includes false positive guidance. General principles:

1. **Test files**: Use `.shieldpmignore` or `--includeTests=false` to skip test directories
2. **Development config**: Rules flag dev-mode settings — add `NODE_ENV` guards
3. **Validated input**: If input is validated before use, the finding may be a false positive
4. **Intentional patterns**: Add inline comments `// shieldpm-ignore: <rule-id>` (planned)

---

## Comparison with Other Tools

| Capability | ShieldPM | Semgrep | ESLint Security | Snyk Code |
|-----------|----------|---------|-----------------|-----------|
| OWASP Top 10 mapping | All 10 | All 10 | Partial | All 10 |
| Rules included | 120+ | 2000+ | 30+ | Proprietary |
| CWE mapping | Yes | Yes | Partial | Yes |
| Fix suggestions | Every rule | Some | No | Some |
| False positive guidance | Every rule | No | No | No |
| Dependency scanning | Yes | No | No | Yes |
| SBOM generation | Yes | No | No | No |
| License compliance | Yes | No | No | Yes |
| Compliance reports | SOC2/ISO/PCI | No | No | No |
| Zero dependencies | Yes | No (Python) | No (Node) | No (Cloud) |
| Offline capable | Yes | Yes | Yes | No |
| Free & open source | Yes | Community | Yes | Freemium |
| CI/CD generators | Yes | No | No | Yes |
| HTML reports | Yes | No | No | Yes |
| Pre-commit hooks | Yes | Yes | Yes | No |

ShieldPM trades breadth of rules (Semgrep has more) for **depth of integration** — combining source scanning, dependency analysis, SBOM, licenses, compliance, and CI/CD in a single zero-dependency tool.
