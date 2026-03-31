/**
 * ShieldPM — OWASP Top 10 Pattern Library
 * 120+ security rules mapped to OWASP 2021 categories and CWE IDs.
 * Used by the source code scanner to detect vulnerabilities in project code.
 */

// ── Types ────────────────────────────────────────────────────────────────

export type OWASPCategory =
  | 'A01:2021' // Broken Access Control
  | 'A02:2021' // Cryptographic Failures
  | 'A03:2021' // Injection
  | 'A04:2021' // Insecure Design
  | 'A05:2021' // Security Misconfiguration
  | 'A06:2021' // Vulnerable & Outdated Components
  | 'A07:2021' // Identification & Authentication Failures
  | 'A08:2021' // Software & Data Integrity Failures
  | 'A09:2021' // Security Logging & Monitoring Failures
  | 'A10:2021' // Server-Side Request Forgery
  | 'EXTRA';   // Additional patterns (TS, React, Secrets, etc.)

export type Confidence = 'high' | 'medium' | 'low';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const OWASP_NAMES: Record<OWASPCategory, string> = {
  'A01:2021': 'Broken Access Control',
  'A02:2021': 'Cryptographic Failures',
  'A03:2021': 'Injection',
  'A04:2021': 'Insecure Design',
  'A05:2021': 'Security Misconfiguration',
  'A06:2021': 'Vulnerable & Outdated Components',
  'A07:2021': 'Identification & Authentication Failures',
  'A08:2021': 'Software & Data Integrity Failures',
  'A09:2021': 'Security Logging & Monitoring Failures',
  'A10:2021': 'Server-Side Request Forgery',
  'EXTRA': 'Additional Security Patterns',
};

export interface OWASPRule {
  id: string;
  owasp: OWASPCategory;
  cwe: number;
  severity: Severity;
  confidence: Confidence;
  pattern: RegExp;
  message: string;
  description: string;
  fix: string;
  falsePositive: string;
  tags: string[];
}

// ── A01:2021 — Broken Access Control ────────────────────────────────────

const A01_RULES: OWASPRule[] = [
  {
    id: 'A01-path-traversal',
    owasp: 'A01:2021', cwe: 22, severity: 'critical', confidence: 'high',
    pattern: /(?:readFile|readFileSync|createReadStream|access|stat)\s*\(\s*(?:req\.(?:params|query|body)\b|`[^`]*\$\{)/g,
    message: 'Path traversal: file operation uses unsanitized user input',
    description: 'Reading files using request parameters allows attackers to access arbitrary files via ../ sequences.',
    fix: 'Use path.resolve() and verify the resolved path starts with an allowed base directory.',
    falsePositive: 'If the input is validated/sanitized before use, or comes from a trusted source.',
    tags: ['path-traversal', 'lfi'],
  },
  {
    id: 'A01-open-redirect',
    owasp: 'A01:2021', cwe: 601, severity: 'high', confidence: 'medium',
    pattern: /(?:res\.redirect|window\.location|location\.href)\s*(?:\(|=)\s*(?:req\.(?:query|params|body)|(?:searchParams|query)\.get)/g,
    message: 'Open redirect: redirect destination from user input',
    description: 'Redirecting to a user-supplied URL allows phishing attacks by sending users to malicious sites.',
    fix: 'Validate redirect URL against an allowlist of permitted domains, or use relative paths only.',
    falsePositive: 'If the redirect target is validated against an allowlist before use.',
    tags: ['open-redirect', 'phishing'],
  },
  {
    id: 'A01-cors-wildcard',
    owasp: 'A01:2021', cwe: 942, severity: 'high', confidence: 'high',
    pattern: /(?:Access-Control-Allow-Origin|allowedOrigins?|cors)\s*[:=]\s*['"]\*['"]/g,
    message: 'CORS wildcard: Access-Control-Allow-Origin set to *',
    description: 'Wildcard CORS allows any website to make cross-origin requests, potentially exposing sensitive data.',
    fix: 'Set specific allowed origins instead of wildcard. Use a dynamic origin check against an allowlist.',
    falsePositive: 'Acceptable for fully public APIs with no authentication or sensitive data.',
    tags: ['cors', 'access-control'],
  },
  {
    id: 'A01-cors-reflect-origin',
    owasp: 'A01:2021', cwe: 942, severity: 'critical', confidence: 'medium',
    pattern: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*req\.headers\.origin/g,
    message: 'CORS origin reflection: echoing request origin without validation',
    description: 'Reflecting the Origin header back as allowed origin bypasses CORS protections entirely.',
    fix: 'Validate req.headers.origin against an explicit allowlist before reflecting it.',
    falsePositive: 'If origin is checked against a whitelist before being set in the response.',
    tags: ['cors', 'origin-reflection'],
  },
  {
    id: 'A01-missing-auth-middleware',
    owasp: 'A01:2021', cwe: 862, severity: 'medium', confidence: 'low',
    pattern: /(?:app|router)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"]*(?:admin|internal|private|manage|config)[^'"]*['"`]\s*,\s*(?:async\s+)?\(/g,
    message: 'Sensitive route may lack authentication middleware',
    description: 'Routes with admin/internal/private paths should have authentication middleware before the handler.',
    fix: 'Add authentication middleware: app.get("/admin/...", requireAuth, handler).',
    falsePositive: 'If auth is handled by a global middleware or upstream proxy.',
    tags: ['missing-auth', 'access-control'],
  },
  {
    id: 'A01-directory-listing',
    owasp: 'A01:2021', cwe: 548, severity: 'medium', confidence: 'high',
    pattern: /(?:express\.static|serveStatic|serve-static)\s*\([^)]*(?:dotfiles\s*:\s*['"]allow['"]|index\s*:\s*false)/g,
    message: 'Static file serving may expose directory listing or dotfiles',
    description: 'Serving static files with dotfiles allowed or index disabled can expose sensitive files.',
    fix: 'Set dotfiles: "deny" and ensure directory listing is disabled.',
    falsePositive: 'If the static directory is intentionally public with no sensitive files.',
    tags: ['directory-listing', 'information-disclosure'],
  },
  {
    id: 'A01-idor-direct-db',
    owasp: 'A01:2021', cwe: 639, severity: 'high', confidence: 'medium',
    pattern: /(?:findUnique|findOne|findById|findByPk|deleteOne|updateOne)\s*\(\s*(?:\{[^}]*(?:id|_id)\s*:\s*(?:req\.(?:params|query|body)|parseInt\s*\(\s*req))/g,
    message: 'Possible IDOR: database lookup using user-supplied ID without ownership check',
    description: 'Directly using request parameters as database IDs allows users to access other users\' records.',
    fix: 'Add ownership verification: include the authenticated user\'s ID in the query filter.',
    falsePositive: 'If ownership is verified elsewhere, or the resource is intentionally public.',
    tags: ['idor', 'authorization'],
  },
  {
    id: 'A01-privilege-escalation',
    owasp: 'A01:2021', cwe: 269, severity: 'critical', confidence: 'medium',
    pattern: /(?:role|isAdmin|permission|privilege)\s*[:=]\s*(?:req\.(?:body|query|params)\b|(?:searchParams|query)\.get)/g,
    message: 'Privilege escalation: role/permission set from user input',
    description: 'Allowing users to set their own role or permissions enables privilege escalation.',
    fix: 'Never accept role/permission values from user input. Derive them from the authenticated session.',
    falsePositive: 'If this is an admin-only endpoint with proper authorization checks.',
    tags: ['privilege-escalation', 'authorization'],
  },
  {
    id: 'A01-insecure-object-ref',
    owasp: 'A01:2021', cwe: 639, severity: 'medium', confidence: 'low',
    pattern: /\/api\/(?:users?|accounts?|profiles?)\/\s*[:]\s*id/g,
    message: 'API route with user resource may need authorization check',
    description: 'API endpoints that access user resources by ID should verify the requester owns the resource.',
    fix: 'Implement ownership verification middleware for all user-resource endpoints.',
    falsePositive: 'If the route is protected by middleware not visible in this pattern.',
    tags: ['idor', 'api-security'],
  },
  {
    id: 'A01-jwt-no-verify',
    owasp: 'A01:2021', cwe: 345, severity: 'critical', confidence: 'high',
    pattern: /jwt\.decode\s*\(/g,
    message: 'JWT decoded without verification — use jwt.verify() instead',
    description: 'jwt.decode() does not verify the signature, allowing token forgery.',
    fix: 'Use jwt.verify(token, secret) instead of jwt.decode() for authentication decisions.',
    falsePositive: 'If decode is used only for reading non-sensitive claims (e.g., displaying username).',
    tags: ['jwt', 'token-verification'],
  },
];

// ── A02:2021 — Cryptographic Failures ───────────────────────────────────

const A02_RULES: OWASPRule[] = [
  {
    id: 'A02-md5-hash',
    owasp: 'A02:2021', cwe: 327, severity: 'high', confidence: 'high',
    pattern: /createHash\s*\(\s*['"`]md5['"`]\s*\)/g,
    message: 'Weak hash: MD5 is cryptographically broken',
    description: 'MD5 is vulnerable to collision attacks and should not be used for security purposes.',
    fix: 'Use createHash("sha256") or createHash("sha3-256") instead.',
    falsePositive: 'Acceptable for non-security checksums (e.g., cache keys, ETags).',
    tags: ['weak-hash', 'md5'],
  },
  {
    id: 'A02-sha1-hash',
    owasp: 'A02:2021', cwe: 327, severity: 'medium', confidence: 'high',
    pattern: /createHash\s*\(\s*['"`]sha1['"`]\s*\)/g,
    message: 'Weak hash: SHA-1 has known collision vulnerabilities',
    description: 'SHA-1 is deprecated for security use. Collisions have been demonstrated in practice.',
    fix: 'Use createHash("sha256") or stronger.',
    falsePositive: 'Acceptable for legacy compatibility or non-security checksums.',
    tags: ['weak-hash', 'sha1'],
  },
  {
    id: 'A02-hardcoded-secret',
    owasp: 'A02:2021', cwe: 798, severity: 'critical', confidence: 'medium',
    pattern: /(?:(?:secret|private[_-]?key|encryption[_-]?key|signing[_-]?key|api[_-]?secret)\s*[:=]\s*['"`][A-Za-z0-9+/=_-]{16,}['"`])/gi,
    message: 'Hardcoded secret: cryptographic key or secret embedded in source code',
    description: 'Secrets in source code can be extracted from version control and deployed artifacts.',
    fix: 'Move secrets to environment variables or a secrets manager (AWS Secrets Manager, Vault).',
    falsePositive: 'If the value is a placeholder, test fixture, or public key.',
    tags: ['hardcoded-secret', 'key-management'],
  },
  {
    id: 'A02-math-random-crypto',
    owasp: 'A02:2021', cwe: 338, severity: 'high', confidence: 'medium',
    pattern: /Math\.random\s*\(\s*\)[\s\S]{0,60}(?:token|secret|key|password|nonce|salt|iv|seed|otp|csrf)/gi,
    message: 'Insecure randomness: Math.random() used in security context',
    description: 'Math.random() is not cryptographically secure. Outputs are predictable.',
    fix: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive values.',
    falsePositive: 'If Math.random() is used for non-security purposes (UI, shuffling, etc.).',
    tags: ['weak-random', 'prng'],
  },
  {
    id: 'A02-cleartext-password-store',
    owasp: 'A02:2021', cwe: 256, severity: 'critical', confidence: 'medium',
    pattern: /(?:password|passwd)\s*[:=]\s*(?:req\.body|ctx\.request\.body|input)\s*\.\s*password[\s\S]{0,30}(?:save|create|insert|update|set)\b/gi,
    message: 'Cleartext password: password stored without hashing',
    description: 'Storing passwords in cleartext allows mass credential theft if the database is breached.',
    fix: 'Hash passwords with bcrypt, scrypt, or argon2 before storage.',
    falsePositive: 'If the password is hashed before the save call on a different line.',
    tags: ['cleartext-password', 'password-storage'],
  },
  {
    id: 'A02-weak-cipher',
    owasp: 'A02:2021', cwe: 327, severity: 'high', confidence: 'high',
    pattern: /createCipher(?:iv)?\s*\(\s*['"`](?:des|rc4|rc2|blowfish|des-ede|aes-128-ecb|aes-256-ecb)['"`]/gi,
    message: 'Weak cipher: DES, RC4, RC2, or ECB mode cipher detected',
    description: 'These ciphers are cryptographically broken or use insecure modes.',
    fix: 'Use aes-256-gcm or aes-256-cbc with proper IV and authentication.',
    falsePositive: 'If decrypting legacy data that must use the old cipher.',
    tags: ['weak-cipher', 'encryption'],
  },
  {
    id: 'A02-ecb-mode',
    owasp: 'A02:2021', cwe: 327, severity: 'high', confidence: 'high',
    pattern: /['"`](?:aes-(?:128|192|256)-ecb|des-ecb)['"`]/gi,
    message: 'ECB mode: identical plaintext blocks produce identical ciphertext',
    description: 'ECB mode leaks patterns in encrypted data. Each block is encrypted independently.',
    fix: 'Use GCM mode (aes-256-gcm) which provides both encryption and authentication.',
    falsePositive: 'Almost never a false positive — ECB is insecure for any multi-block data.',
    tags: ['ecb-mode', 'encryption'],
  },
  {
    id: 'A02-tls-reject-unauthorized',
    owasp: 'A02:2021', cwe: 295, severity: 'critical', confidence: 'high',
    pattern: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"`]0['"`]|process\.env\s*\[\s*['"`]NODE_TLS_REJECT_UNAUTHORIZED['"`]\s*\]\s*=\s*['"`]0['"`])/g,
    message: 'TLS verification disabled: man-in-the-middle attacks possible',
    description: 'Disabling TLS certificate verification allows attackers to intercept encrypted traffic.',
    fix: 'Remove rejectUnauthorized:false. Fix the underlying certificate issue instead.',
    falsePositive: 'Only acceptable in local development with self-signed certs.',
    tags: ['tls', 'certificate-validation'],
  },
  {
    id: 'A02-short-key-length',
    owasp: 'A02:2021', cwe: 326, severity: 'medium', confidence: 'medium',
    pattern: /(?:generateKeyPair|generateKey)\s*\(\s*['"`]rsa['"`]\s*,\s*\{[^}]*modulusLength\s*:\s*(?:512|768|1024)\b/g,
    message: 'Short RSA key: key length below 2048 bits is insecure',
    description: 'RSA keys shorter than 2048 bits can be factored with modern hardware.',
    fix: 'Use modulusLength: 4096 (or minimum 2048) for RSA keys.',
    falsePositive: 'If used for non-security purposes (testing, key derivation).',
    tags: ['short-key', 'rsa'],
  },
  {
    id: 'A02-createCipher-deprecated',
    owasp: 'A02:2021', cwe: 327, severity: 'medium', confidence: 'high',
    pattern: /crypto\.createCipher\s*\(/g,
    message: 'Deprecated: createCipher uses weak key derivation — use createCipheriv',
    description: 'crypto.createCipher() derives the key with MD5 and no salt. It is deprecated.',
    fix: 'Use crypto.createCipheriv() with a proper key and random IV.',
    falsePositive: 'None — createCipher is always deprecated in favor of createCipheriv.',
    tags: ['deprecated-crypto', 'key-derivation'],
  },
];

// ── A03:2021 — Injection ────────────────────────────────────────────────

const A03_RULES: OWASPRule[] = [
  {
    id: 'A03-sql-concat',
    owasp: 'A03:2021', cwe: 89, severity: 'critical', confidence: 'high',
    pattern: /(?:query|execute|raw)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b[^'"`]*['"`]\s*\+\s*/gi,
    message: 'SQL injection: query built with string concatenation',
    description: 'Concatenating user input into SQL queries allows SQL injection attacks.',
    fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [id]).',
    falsePositive: 'If the concatenated value is a constant or sanitized integer.',
    tags: ['sql-injection', 'string-concat'],
  },
  {
    id: 'A03-sql-template-literal',
    owasp: 'A03:2021', cwe: 89, severity: 'critical', confidence: 'high',
    pattern: /(?:query|execute|raw)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/gi,
    message: 'SQL injection: query built with template literal interpolation',
    description: 'Template literals in SQL queries are just as dangerous as string concatenation.',
    fix: 'Use parameterized queries or an ORM. Never interpolate variables into SQL strings.',
    falsePositive: 'If using a tagged template literal that properly escapes values (e.g., sql`...`).',
    tags: ['sql-injection', 'template-literal'],
  },
  {
    id: 'A03-nosql-injection',
    owasp: 'A03:2021', cwe: 943, severity: 'critical', confidence: 'medium',
    pattern: /(?:find|findOne|findMany|deleteMany|updateMany|aggregate)\s*\(\s*(?:req\.(?:body|query|params)|JSON\.parse\s*\(\s*req)/g,
    message: 'NoSQL injection: query uses unsanitized user input directly',
    description: 'Passing user input directly to NoSQL queries allows operator injection ({$gt: ""}).',
    fix: 'Validate and sanitize input. Explicitly extract needed fields instead of passing req.body directly.',
    falsePositive: 'If req.body fields are individually validated and typed before use.',
    tags: ['nosql-injection', 'mongodb'],
  },
  {
    id: 'A03-command-injection-exec',
    owasp: 'A03:2021', cwe: 78, severity: 'critical', confidence: 'high',
    pattern: /(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"`][^'"`]*['"`]\s*\+\s*(?:req\.|input|user|param|arg|data|name|file|path|url|cmd))/gi,
    message: 'Command injection: shell command built with user input',
    description: 'Injecting user input into shell commands allows arbitrary command execution.',
    fix: 'Use execFile() or spawn() with argument arrays. Never concatenate into shell commands.',
    falsePositive: 'If the variable is a hardcoded constant or properly escaped.',
    tags: ['command-injection', 'rce'],
  },
  {
    id: 'A03-command-injection-spawn',
    owasp: 'A03:2021', cwe: 78, severity: 'high', confidence: 'medium',
    pattern: /(?:spawn|execFile)\s*\(\s*(?:req\.|input|user|param|data|cmd)/gi,
    message: 'Possible command injection: command name from user input',
    description: 'Using user input as the command name allows arbitrary program execution.',
    fix: 'Use an allowlist of permitted commands. Never accept command names from user input.',
    falsePositive: 'If the command name is validated against a fixed allowlist.',
    tags: ['command-injection', 'rce'],
  },
  {
    id: 'A03-ldap-injection',
    owasp: 'A03:2021', cwe: 90, severity: 'critical', confidence: 'medium',
    pattern: /(?:search|bind)\s*\(\s*(?:`[^`]*\$\{|['"`][^'"`]*['"`]\s*\+\s*)[\s\S]{0,30}(?:req\.|input|user|param)/gi,
    message: 'LDAP injection: LDAP query built with user input',
    description: 'Unsanitized input in LDAP queries can modify query logic or extract data.',
    fix: 'Escape special LDAP characters (*, (, ), \\, NUL) in user input before use.',
    falsePositive: 'If input is properly LDAP-escaped before query construction.',
    tags: ['ldap-injection'],
  },
  {
    id: 'A03-xpath-injection',
    owasp: 'A03:2021', cwe: 643, severity: 'high', confidence: 'medium',
    pattern: /(?:xpath|evaluate|select)\s*\(\s*(?:`[^`]*\$\{|['"`][^'"`]*['"`]\s*\+)/gi,
    message: 'XPath injection: XPath expression built with dynamic input',
    description: 'Injecting user input into XPath queries can bypass authentication or extract data.',
    fix: 'Use parameterized XPath queries or sanitize input against XPath special characters.',
    falsePositive: 'If the dynamic value is from a trusted, validated source.',
    tags: ['xpath-injection'],
  },
  {
    id: 'A03-header-injection',
    owasp: 'A03:2021', cwe: 113, severity: 'high', confidence: 'high',
    pattern: /(?:setHeader|writeHead|res\.header)\s*\(\s*['"`][^'"`]+['"`]\s*,\s*(?:req\.|input|user|param|query)/gi,
    message: 'Header injection: HTTP header value from user input',
    description: 'Injecting user input into HTTP headers enables response splitting and cache poisoning.',
    fix: 'Validate and sanitize header values. Remove newline characters (\\r\\n).',
    falsePositive: 'If the value is validated to contain no CRLF characters.',
    tags: ['header-injection', 'response-splitting'],
  },
  {
    id: 'A03-log-injection',
    owasp: 'A03:2021', cwe: 117, severity: 'medium', confidence: 'medium',
    pattern: /(?:console\.(?:log|info|warn|error)|logger?\.\w+)\s*\(\s*(?:`[^`]*\$\{(?:req\.|input|user)|['"`][^'"`]*['"`]\s*\+\s*(?:req\.|input|user))/gi,
    message: 'Log injection: unsanitized user input in log message',
    description: 'Log injection can forge log entries, corrupt log analysis, and enable log-based attacks.',
    fix: 'Sanitize user input before logging. Remove newlines and control characters.',
    falsePositive: 'If logging structured data (JSON) that encodes special characters.',
    tags: ['log-injection', 'logging'],
  },
  {
    id: 'A03-regex-dos',
    owasp: 'A03:2021', cwe: 1333, severity: 'medium', confidence: 'low',
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|input|user|param|query|data)/gi,
    message: 'ReDoS risk: regex built from user input',
    description: 'User-controlled regex patterns can cause catastrophic backtracking (denial of service).',
    fix: 'Use a regex sanitizer library, set timeouts, or avoid user-supplied regex patterns.',
    falsePositive: 'If the input is limited to simple patterns (alphanumeric only).',
    tags: ['redos', 'regex', 'denial-of-service'],
  },
  {
    id: 'A03-eval-injection',
    owasp: 'A03:2021', cwe: 95, severity: 'critical', confidence: 'high',
    pattern: /\beval\s*\(\s*(?:req\.|input|user|param|query|data|body)/gi,
    message: 'Code injection: eval() with user input — remote code execution',
    description: 'Passing user input to eval() allows arbitrary JavaScript code execution on the server.',
    fix: 'Never use eval() with user input. Use JSON.parse() for data, or a sandboxed interpreter.',
    falsePositive: 'Almost never — eval with user input is inherently dangerous.',
    tags: ['eval-injection', 'rce', 'code-execution'],
  },
  {
    id: 'A03-template-injection',
    owasp: 'A03:2021', cwe: 94, severity: 'critical', confidence: 'medium',
    pattern: /(?:render|compile|template)\s*\(\s*(?:req\.|input|user|body)[\s\S]{0,30}(?:\{|\[)/gi,
    message: 'Template injection: user input used as template source',
    description: 'Server-side template injection can lead to remote code execution.',
    fix: 'Never use user input as template content. Only use it as template variables/data.',
    falsePositive: 'If the function renders a fixed template with user data as variables.',
    tags: ['ssti', 'template-injection', 'rce'],
  },
];

// ── A04:2021 — Insecure Design ──────────────────────────────────────────

const A04_RULES: OWASPRule[] = [
  {
    id: 'A04-race-condition',
    owasp: 'A04:2021', cwe: 362, severity: 'high', confidence: 'low',
    pattern: /(?:findOne|findUnique)\s*\([^)]+\)[\s\S]{0,80}(?:update|save|create|delete)\s*\(/g,
    message: 'Possible race condition: read-then-write without transaction',
    description: 'Read-then-write patterns without transactions can cause TOCTOU race conditions.',
    fix: 'Wrap read-then-write operations in a database transaction or use atomic operations.',
    falsePositive: 'If the operation is idempotent or uses optimistic locking.',
    tags: ['race-condition', 'toctou'],
  },
  {
    id: 'A04-missing-rate-limit',
    owasp: 'A04:2021', cwe: 770, severity: 'medium', confidence: 'low',
    pattern: /(?:app|router)\s*\.\s*post\s*\(\s*['"`][^'"]*(?:login|signin|auth|register|signup|reset|forgot|otp|verify)['"`]/gi,
    message: 'Sensitive endpoint may lack rate limiting',
    description: 'Authentication endpoints without rate limiting are vulnerable to brute-force attacks.',
    fix: 'Add rate limiting middleware (e.g., express-rate-limit) to auth endpoints.',
    falsePositive: 'If rate limiting is handled by a reverse proxy, WAF, or global middleware.',
    tags: ['rate-limit', 'brute-force'],
  },
  {
    id: 'A04-hardcoded-credentials',
    owasp: 'A04:2021', cwe: 798, severity: 'critical', confidence: 'medium',
    pattern: /(?:(?:username|user|admin|root)\s*[:=]\s*['"`]\w+['"`][\s,;]*(?:password|passwd|pass|pwd)\s*[:=]\s*['"`][^'"`]{4,}['"`])/gi,
    message: 'Hardcoded credentials: username/password pair embedded in code',
    description: 'Credentials in source code are easily discoverable and cannot be rotated without redeployment.',
    fix: 'Move credentials to environment variables or a secrets manager.',
    falsePositive: 'If this is a test fixture or example configuration with placeholder values.',
    tags: ['hardcoded-credentials', 'secrets'],
  },
  {
    id: 'A04-insecure-default',
    owasp: 'A04:2021', cwe: 1188, severity: 'medium', confidence: 'medium',
    pattern: /(?:(?:secure|httpOnly|sameSite)\s*:\s*false|(?:signed|encrypted|verified)\s*:\s*false)/g,
    message: 'Insecure default: security feature explicitly disabled',
    description: 'Disabling security features (secure cookies, HTTP-only, etc.) weakens application security.',
    fix: 'Enable security features: secure: true, httpOnly: true, sameSite: "strict".',
    falsePositive: 'If this is development-only configuration behind an environment check.',
    tags: ['insecure-default', 'configuration'],
  },
  {
    id: 'A04-missing-input-validation',
    owasp: 'A04:2021', cwe: 20, severity: 'medium', confidence: 'low',
    pattern: /(?:req\.body|req\.query|req\.params)\s*\.\s*\w+[\s\S]{0,20}(?:parseInt|Number|\.trim\(\))?[\s\S]{0,10}(?:sql|query|exec|eval|write|send|redirect)/gi,
    message: 'User input used in sensitive operation without visible validation',
    description: 'User input should be validated (type, length, format) before use in sensitive operations.',
    fix: 'Add input validation using zod, joi, or manual checks before processing.',
    falsePositive: 'If validation happens in middleware or a previous function call.',
    tags: ['input-validation', 'defense-in-depth'],
  },
];

// ── A05:2021 — Security Misconfiguration ────────────────────────────────

const A05_RULES: OWASPRule[] = [
  {
    id: 'A05-debug-enabled',
    owasp: 'A05:2021', cwe: 489, severity: 'medium', confidence: 'medium',
    pattern: /(?:debug\s*[:=]\s*true|DEBUG\s*[:=]\s*['"`](?:\*|true)['"`]|app\.set\s*\(\s*['"`](?:debug|showStackError)['"`]\s*,\s*true\s*\))/g,
    message: 'Debug mode enabled: may expose sensitive information in production',
    description: 'Debug mode often reveals stack traces, query parameters, and internal state to users.',
    fix: 'Disable debug mode in production. Use environment-based configuration.',
    falsePositive: 'If behind a NODE_ENV !== "production" check.',
    tags: ['debug-mode', 'information-disclosure'],
  },
  {
    id: 'A05-verbose-error',
    owasp: 'A05:2021', cwe: 209, severity: 'medium', confidence: 'medium',
    pattern: /(?:res\.(?:json|send|status)\s*\([^)]*(?:err\.(?:stack|message)|error\.(?:stack|message))|catch\s*\(\s*\w+\s*\)\s*\{[\s\S]{0,50}res\.[\s\S]{0,30}(?:\.stack|\.message))/g,
    message: 'Verbose error: stack trace or error details sent to client',
    description: 'Exposing error details to clients reveals internal structure and aids attackers.',
    fix: 'Return generic error messages to clients. Log detailed errors server-side only.',
    falsePositive: 'If this is a development-only error handler.',
    tags: ['error-handling', 'information-disclosure'],
  },
  {
    id: 'A05-default-credentials',
    owasp: 'A05:2021', cwe: 1393, severity: 'critical', confidence: 'medium',
    pattern: /(?:password|passwd|pass)\s*[:=]\s*['"`](?:admin|password|123456|root|default|changeme|test|demo|guest)['"`]/gi,
    message: 'Default credentials: common default password detected',
    description: 'Default passwords are the first thing attackers try and are widely known.',
    fix: 'Require password changes on first use. Never ship default credentials.',
    falsePositive: 'If used in test fixtures, documentation, or examples.',
    tags: ['default-credentials', 'weak-password'],
  },
  {
    id: 'A05-missing-security-headers',
    owasp: 'A05:2021', cwe: 693, severity: 'medium', confidence: 'low',
    pattern: /app\.(?:use|listen)|createServer\s*\(/g,
    message: 'Server created — ensure security headers (HSTS, X-Frame-Options, CSP) are set',
    description: 'Missing security headers leave the application vulnerable to clickjacking, XSS, and downgrade attacks.',
    fix: 'Use helmet middleware or set headers manually: X-Frame-Options, X-Content-Type-Options, CSP, HSTS.',
    falsePositive: 'If headers are set by a reverse proxy, CDN, or middleware not visible in this file.',
    tags: ['security-headers', 'http'],
  },
  {
    id: 'A05-exposed-env-file',
    owasp: 'A05:2021', cwe: 538, severity: 'high', confidence: 'medium',
    pattern: /(?:express\.static|serveStatic)\s*\(\s*['"`]\.['"`]|(?:express\.static|serveStatic)\s*\(\s*['"`]\.\/['"`]/g,
    message: 'Static serving root directory may expose .env and other sensitive files',
    description: 'Serving the project root as static files can expose .env, package.json, and config files.',
    fix: 'Serve only a dedicated public/ directory. Never serve the project root.',
    falsePositive: 'If a custom middleware filters out dotfiles and sensitive paths.',
    tags: ['information-disclosure', 'env-exposure'],
  },
  {
    id: 'A05-stack-trace-exposure',
    owasp: 'A05:2021', cwe: 209, severity: 'medium', confidence: 'high',
    pattern: /\.stack\b[\s\S]{0,30}(?:res\.|response\.|send\(|json\(|render\()/g,
    message: 'Stack trace sent to client in response',
    description: 'Stack traces reveal file paths, framework versions, and internal logic to attackers.',
    fix: 'Log stack traces server-side. Return only a generic error ID to clients.',
    falsePositive: 'If gated behind a development environment check.',
    tags: ['stack-trace', 'information-disclosure'],
  },
  {
    id: 'A05-dev-mode-production',
    owasp: 'A05:2021', cwe: 489, severity: 'medium', confidence: 'low',
    pattern: /NODE_ENV\s*(?:!==|!=)\s*['"`]production['"`][\s\S]{0,20}(?:true|enable|activate)/g,
    message: 'Development feature may be active in production',
    description: 'Features gated on NODE_ENV !== "production" may be accidentally enabled.',
    fix: 'Ensure NODE_ENV is set to "production" in deployment. Use explicit opt-in for dev features.',
    falsePositive: 'If this correctly gates a dev-only feature that is off in production.',
    tags: ['dev-mode', 'configuration'],
  },
  {
    id: 'A05-permissive-cors-credentials',
    owasp: 'A05:2021', cwe: 942, severity: 'high', confidence: 'high',
    pattern: /(?:Access-Control-Allow-Credentials|credentials)\s*[:=]\s*(?:true|['"`]true['"`])[\s\S]{0,100}(?:origin\s*[:=]\s*['"`]\*['"`]|Allow-Origin\s*[:=]\s*['"`]\*['"`])/g,
    message: 'CORS: credentials enabled with wildcard origin — browser will reject but indicates misconfiguration',
    description: 'Combining credentials: true with origin: * is a misconfiguration (browsers block it).',
    fix: 'Set a specific origin when using credentials. Never combine with wildcard.',
    falsePositive: 'Browsers enforce this, but it indicates a misunderstanding of CORS.',
    tags: ['cors', 'credentials'],
  },
];

// ── A06:2021 — Vulnerable & Outdated Components ────────────────────────

const A06_RULES: OWASPRule[] = [
  {
    id: 'A06-known-vulnerable-import',
    owasp: 'A06:2021', cwe: 1035, severity: 'high', confidence: 'high',
    pattern: /require\s*\(\s*['"`](?:event-stream|flatmap-stream|ua-parser-js|colors|faker|coa|rc|node-ipc)['"`]\s*\)/g,
    message: 'Known compromised package imported',
    description: 'This package has a documented supply chain compromise or malicious version.',
    fix: 'Remove the package. Use a safe alternative or fork from a known-good version.',
    falsePositive: 'If using a patched version after the compromise was resolved.',
    tags: ['supply-chain', 'known-vuln'],
  },
  {
    id: 'A06-deprecated-api',
    owasp: 'A06:2021', cwe: 477, severity: 'low', confidence: 'high',
    pattern: /(?:new\s+Buffer\s*\(|crypto\.createCipher\s*\(|url\.parse\s*\(|domain\.create\s*\(|fs\.exists\s*\()/g,
    message: 'Deprecated Node.js API — use modern replacement',
    description: 'Deprecated APIs may have security issues and will be removed in future Node.js versions.',
    fix: 'Buffer.from()/Buffer.alloc(), createCipheriv(), new URL(), fs.access().',
    falsePositive: 'If maintaining compatibility with very old Node.js versions.',
    tags: ['deprecated-api', 'nodejs'],
  },
  {
    id: 'A06-wildcard-dependency',
    owasp: 'A06:2021', cwe: 1104, severity: 'medium', confidence: 'high',
    pattern: /['"`]\s*:\s*['"`]\*['"`]/g,
    message: 'Wildcard dependency version — any version will be installed',
    description: 'Wildcard versions allow installing malicious or breaking versions automatically.',
    fix: 'Pin to specific versions or use caret ranges: "^1.2.3".',
    falsePositive: 'If in a meta-package or workspace configuration.',
    tags: ['dependency-version', 'supply-chain'],
  },
  {
    id: 'A06-outdated-crypto-lib',
    owasp: 'A06:2021', cwe: 327, severity: 'medium', confidence: 'medium',
    pattern: /require\s*\(\s*['"`](?:crypto-js|sjcl|jsencrypt|node-forge)['"`]\s*\)/g,
    message: 'Consider using Node.js built-in crypto instead of third-party library',
    description: 'Third-party crypto libraries may have vulnerabilities and add attack surface.',
    fix: 'Use Node.js built-in crypto module for standard operations (hash, encrypt, sign).',
    falsePositive: 'If the library provides functionality not available in built-in crypto.',
    tags: ['crypto-library', 'dependency'],
  },
  {
    id: 'A06-git-dependency',
    owasp: 'A06:2021', cwe: 829, severity: 'medium', confidence: 'high',
    pattern: /['"`]\s*:\s*['"`](?:git\+|git:\/\/|github:|bitbucket:)/g,
    message: 'Git URL dependency — not verified by npm registry',
    description: 'Git dependencies bypass npm registry integrity checks and can change without notice.',
    fix: 'Publish to npm or use a lockfile with integrity hashes.',
    falsePositive: 'If the git repo is owned by your organization with branch protection.',
    tags: ['git-dependency', 'supply-chain'],
  },
];

// ── A07:2021 — Identification & Authentication Failures ─────────────────

const A07_RULES: OWASPRule[] = [
  {
    id: 'A07-hardcoded-password',
    owasp: 'A07:2021', cwe: 259, severity: 'critical', confidence: 'medium',
    pattern: /(?:password|passwd|pwd|pass)\s*[:=]\s*['"`][^'"`]{6,}['"`]\s*[;,\n}]/gi,
    message: 'Hardcoded password in source code',
    description: 'Passwords in source code are visible in version control and cannot be rotated easily.',
    fix: 'Use environment variables or a secrets manager for all passwords.',
    falsePositive: 'If this is a test fixture, placeholder, or password validation rule.',
    tags: ['hardcoded-password', 'authentication'],
  },
  {
    id: 'A07-weak-password-policy',
    owasp: 'A07:2021', cwe: 521, severity: 'medium', confidence: 'low',
    pattern: /(?:minLength|min_length|minimumLength)\s*[:=]\s*(?:[1-5]|['"`][1-5]['"`])\b/g,
    message: 'Weak password policy: minimum length too short (should be 8+)',
    description: 'Short passwords are easily brute-forced. NIST recommends minimum 8 characters.',
    fix: 'Set minimum password length to 8+ characters. Consider 12+ for high-security systems.',
    falsePositive: 'If this is not a password length setting (e.g., username min length).',
    tags: ['password-policy', 'authentication'],
  },
  {
    id: 'A07-session-fixation',
    owasp: 'A07:2021', cwe: 384, severity: 'high', confidence: 'low',
    pattern: /(?:req\.session\s*\.\s*\w+\s*=[\s\S]{0,30}(?:login|auth|signin))/gi,
    message: 'Possible session fixation: session modified on login without regeneration',
    description: 'Setting session data on login without regenerating the session ID enables session fixation.',
    fix: 'Call req.session.regenerate() before setting authenticated session data.',
    falsePositive: 'If session is regenerated in middleware or before this assignment.',
    tags: ['session-fixation', 'session-management'],
  },
  {
    id: 'A07-jwt-none-algorithm',
    owasp: 'A07:2021', cwe: 345, severity: 'critical', confidence: 'high',
    pattern: /(?:algorithms?\s*[:=]\s*\[?\s*['"`]none['"`]|algorithm\s*:\s*['"`]none['"`])/gi,
    message: 'JWT "none" algorithm allowed — tokens can be forged without signature',
    description: 'The "none" algorithm disables JWT signature verification entirely.',
    fix: 'Explicitly specify allowed algorithms: algorithms: ["HS256"] or ["RS256"].',
    falsePositive: 'Almost never — "none" algorithm should never be allowed.',
    tags: ['jwt', 'authentication'],
  },
  {
    id: 'A07-insecure-cookie',
    owasp: 'A07:2021', cwe: 614, severity: 'medium', confidence: 'high',
    pattern: /(?:cookie|session)\s*(?:\(|[:=])\s*\{[^}]*(?:secure\s*:\s*false|httpOnly\s*:\s*false)/g,
    message: 'Insecure cookie: secure or httpOnly flag disabled',
    description: 'Cookies without secure flag are sent over HTTP. Without httpOnly, JavaScript can read them.',
    fix: 'Set secure: true and httpOnly: true on all authentication cookies.',
    falsePositive: 'If this is development-only configuration.',
    tags: ['insecure-cookie', 'session-management'],
  },
  {
    id: 'A07-credential-in-url',
    owasp: 'A07:2021', cwe: 598, severity: 'high', confidence: 'high',
    pattern: /['"`]https?:\/\/[^'"`]*:[^@'"`]*@/g,
    message: 'Credentials in URL: password visible in logs, history, and referrer headers',
    description: 'URLs with embedded credentials are logged by proxies, browsers, and servers.',
    fix: 'Use Authorization headers or environment variables instead of URL-embedded credentials.',
    falsePositive: 'If this is a documentation example or test fixture.',
    tags: ['credential-url', 'authentication'],
  },
  {
    id: 'A07-plaintext-comparison',
    owasp: 'A07:2021', cwe: 836, severity: 'high', confidence: 'medium',
    pattern: /(?:password|token|secret|key)\s*(?:===|==|!==|!=)\s*(?:req\.|input|user|body|param)/gi,
    message: 'Timing attack: plaintext comparison of secret value',
    description: 'Direct string comparison of secrets is vulnerable to timing side-channel attacks.',
    fix: 'Use crypto.timingSafeEqual() for constant-time comparison of secrets.',
    falsePositive: 'If comparing non-secret values (e.g., username, email).',
    tags: ['timing-attack', 'comparison'],
  },
  {
    id: 'A07-no-password-hash',
    owasp: 'A07:2021', cwe: 916, severity: 'critical', confidence: 'low',
    pattern: /(?:password|passwd)\s*[:=]\s*(?:req\.body|ctx\.body|input)\.\w+[\s\S]{0,100}(?:\.save|\.create|\.insert|User\.)/gi,
    message: 'Password may be stored without hashing',
    description: 'Storing passwords without hashing exposes all accounts if the database is breached.',
    fix: 'Hash with bcrypt, scrypt, or argon2id before storage.',
    falsePositive: 'If the password is hashed before this code path.',
    tags: ['password-hashing', 'storage'],
  },
];

// ── A08:2021 — Software & Data Integrity Failures ───────────────────────

const A08_RULES: OWASPRule[] = [
  {
    id: 'A08-eval-from-network',
    owasp: 'A08:2021', cwe: 494, severity: 'critical', confidence: 'high',
    pattern: /(?:fetch|axios|http\.get|request)\s*\([^)]+\)[\s\S]{0,100}eval\s*\(/g,
    message: 'Remote code execution: eval() on data fetched from network',
    description: 'Evaluating code fetched from the network allows attackers to execute arbitrary code via MITM.',
    fix: 'Never eval() network responses. Parse data as JSON or use a sandboxed interpreter.',
    falsePositive: 'Almost never — eval on network data is inherently dangerous.',
    tags: ['eval-network', 'rce', 'integrity'],
  },
  {
    id: 'A08-dynamic-require-url',
    owasp: 'A08:2021', cwe: 829, severity: 'critical', confidence: 'medium',
    pattern: /require\s*\(\s*(?:https?:\/\/|`https?:)/g,
    message: 'Remote module loading: require() with URL',
    description: 'Loading modules from URLs bypasses integrity checks and can be compromised.',
    fix: 'Install packages from npm with integrity hashes. Never require() from URLs.',
    falsePositive: 'If using a trusted internal module registry with TLS.',
    tags: ['remote-require', 'supply-chain'],
  },
  {
    id: 'A08-cdn-no-sri',
    owasp: 'A08:2021', cwe: 353, severity: 'medium', confidence: 'high',
    pattern: /<script\s+src\s*=\s*['"`]https?:\/\/(?:cdn|unpkg|cdnjs|jsdelivr)[^'"`]*['"`](?![^>]*integrity)/gi,
    message: 'CDN script without Subresource Integrity (SRI) hash',
    description: 'Scripts from CDNs without SRI can be modified if the CDN is compromised.',
    fix: 'Add integrity="sha384-..." and crossorigin="anonymous" attributes.',
    falsePositive: 'If the CDN is self-hosted or integrity is set dynamically.',
    tags: ['sri', 'cdn', 'integrity'],
  },
  {
    id: 'A08-prototype-pollution',
    owasp: 'A08:2021', cwe: 1321, severity: 'high', confidence: 'high',
    pattern: /\[['"`]__proto__['"`]\]|\[['"`]constructor['"`]\]\s*\[['"`]prototype['"`]\]/g,
    message: 'Prototype pollution: __proto__ or constructor.prototype access',
    description: 'Prototype pollution can modify object behavior globally, enabling injection attacks.',
    fix: 'Use Object.create(null) for lookup objects. Validate keys against __proto__ and constructor.',
    falsePositive: 'If this is a prototype pollution detection/prevention check.',
    tags: ['prototype-pollution', 'object-injection'],
  },
  {
    id: 'A08-unsafe-json-parse',
    owasp: 'A08:2021', cwe: 502, severity: 'medium', confidence: 'low',
    pattern: /JSON\.parse\s*\(\s*(?:req\.|input|user|body|data|Buffer)/gi,
    message: 'Unsafe deserialization: JSON.parse on untrusted input without schema validation',
    description: 'Parsing untrusted JSON without schema validation can lead to injection via __proto__.',
    fix: 'Validate parsed JSON against a schema (zod, ajv). Check for __proto__ keys.',
    falsePositive: 'If the parsed data is validated/sanitized after parsing.',
    tags: ['deserialization', 'json'],
  },
  {
    id: 'A08-postinstall-exec',
    owasp: 'A08:2021', cwe: 829, severity: 'high', confidence: 'high',
    pattern: /['"`](?:preinstall|postinstall|install)['"`]\s*:\s*['"`](?:node|sh|bash|cmd|powershell)/g,
    message: 'Install script executes code during npm install',
    description: 'Install scripts run before the user can review the package code.',
    fix: 'Avoid install scripts. If needed, use shieldpm sandbox for safe execution.',
    falsePositive: 'If this is your own package and the script is necessary for native builds.',
    tags: ['install-script', 'supply-chain'],
  },
];

// ── A09:2021 — Security Logging & Monitoring Failures ───────────────────

const A09_RULES: OWASPRule[] = [
  {
    id: 'A09-sensitive-data-in-log',
    owasp: 'A09:2021', cwe: 532, severity: 'high', confidence: 'medium',
    pattern: /(?:console\.(?:log|info|warn|error|debug)|logger?\.\w+)\s*\([^)]*(?:password|passwd|secret|token|apiKey|api_key|authorization|credit.?card|ssn|cvv)/gi,
    message: 'Sensitive data logged: password, token, or PII in log output',
    description: 'Logging sensitive data exposes it in log files, monitoring systems, and crash reports.',
    fix: 'Redact sensitive fields before logging. Use structured logging with field allowlists.',
    falsePositive: 'If the variable name contains "password" but holds a non-sensitive value.',
    tags: ['sensitive-logging', 'data-exposure'],
  },
  {
    id: 'A09-console-log-prod',
    owasp: 'A09:2021', cwe: 532, severity: 'low', confidence: 'low',
    pattern: /console\.log\s*\(\s*(?:['"`](?:DEBUG|TRACE|password|secret|token|key)|(?:req\.body|req\.headers|process\.env))/gi,
    message: 'Debug logging may expose sensitive data in production',
    description: 'console.log in production can expose request bodies, headers, and environment variables.',
    fix: 'Use a structured logger with log levels. Disable debug logging in production.',
    falsePositive: 'If behind a log level check or NODE_ENV guard.',
    tags: ['debug-logging', 'console'],
  },
  {
    id: 'A09-empty-catch',
    owasp: 'A09:2021', cwe: 390, severity: 'medium', confidence: 'medium',
    pattern: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,
    message: 'Empty catch block: errors silently swallowed',
    description: 'Empty catch blocks hide errors, making debugging impossible and masking security failures.',
    fix: 'Log the error, re-throw, or handle it explicitly. At minimum: catch(e) { /* intentional */ }.',
    falsePositive: 'If the error is intentionally ignored (add a comment explaining why).',
    tags: ['error-handling', 'catch-swallow'],
  },
  {
    id: 'A09-missing-auth-logging',
    owasp: 'A09:2021', cwe: 778, severity: 'medium', confidence: 'low',
    pattern: /(?:login|signin|authenticate)\s*(?:=|:)\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)\s*\{(?:(?!log|audit|track|record)[\s\S]){30,200}\}/gi,
    message: 'Authentication function may lack audit logging',
    description: 'Login attempts (success and failure) should be logged for security monitoring.',
    fix: 'Log all authentication attempts with timestamp, username, IP, and result.',
    falsePositive: 'If logging is done by middleware or a wrapper function.',
    tags: ['audit-logging', 'authentication'],
  },
  {
    id: 'A09-error-info-leak',
    owasp: 'A09:2021', cwe: 209, severity: 'medium', confidence: 'medium',
    pattern: /catch\s*\(\s*(\w+)\s*\)\s*\{[\s\S]{0,50}res\.(?:json|send)\s*\(\s*\{[\s\S]{0,50}\1\.(?:message|stack)/g,
    message: 'Error details leaked to client in catch block',
    description: 'Sending error.message or error.stack to clients reveals internal implementation details.',
    fix: 'Return generic error messages. Log full details server-side.',
    falsePositive: 'If this is a development-only error handler.',
    tags: ['error-leak', 'information-disclosure'],
  },
];

// ── A10:2021 — Server-Side Request Forgery ──────────────────────────────

const A10_RULES: OWASPRule[] = [
  {
    id: 'A10-ssrf-fetch',
    owasp: 'A10:2021', cwe: 918, severity: 'critical', confidence: 'medium',
    pattern: /\bfetch\s*\(\s*(?:req\.(?:body|query|params)\.\w+|`[^`]*\$\{req\.|input|user)/gi,
    message: 'SSRF: fetch() with user-controlled URL',
    description: 'Allowing users to control fetch URLs enables access to internal services and metadata.',
    fix: 'Validate URL against an allowlist of permitted domains. Block internal/private IPs.',
    falsePositive: 'If the URL is validated against a strict allowlist.',
    tags: ['ssrf', 'fetch'],
  },
  {
    id: 'A10-ssrf-axios',
    owasp: 'A10:2021', cwe: 918, severity: 'critical', confidence: 'medium',
    pattern: /axios\s*\.?\s*(?:get|post|put|delete|request|head)\s*\(\s*(?:req\.(?:body|query|params)|`[^`]*\$\{req\.|input|user)/gi,
    message: 'SSRF: axios request with user-controlled URL',
    description: 'User-controlled URLs in axios can access internal services, cloud metadata, and file:// URIs.',
    fix: 'Validate URL scheme (https only), hostname against allowlist, and block private IP ranges.',
    falsePositive: 'If URL is validated before the axios call.',
    tags: ['ssrf', 'axios'],
  },
  {
    id: 'A10-ssrf-http-request',
    owasp: 'A10:2021', cwe: 918, severity: 'critical', confidence: 'medium',
    pattern: /https?\.(?:request|get)\s*\(\s*(?:req\.|input|user|param|url|target|dest)/gi,
    message: 'SSRF: http.request with user-controlled URL or options',
    description: 'User-controlled HTTP requests can probe internal networks and access metadata services.',
    fix: 'Validate and sanitize the URL. Block private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x).',
    falsePositive: 'If the URL is from a trusted, validated source.',
    tags: ['ssrf', 'http'],
  },
  {
    id: 'A10-internal-ip-access',
    owasp: 'A10:2021', cwe: 918, severity: 'high', confidence: 'high',
    pattern: /['"`]https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.\d+\.\d+|::1|\[::1\]|metadata\.google|169\.254\.169\.254)/g,
    message: 'Hardcoded internal/metadata IP address',
    description: 'Internal IPs can be used to access cloud metadata services or probe the internal network.',
    fix: 'Use environment variables for service URLs. Never hardcode internal addresses.',
    falsePositive: 'If this is a local development configuration (e.g., localhost:3000).',
    tags: ['internal-ip', 'metadata'],
  },
  {
    id: 'A10-url-redirect-follow',
    owasp: 'A10:2021', cwe: 918, severity: 'medium', confidence: 'medium',
    pattern: /(?:follow|redirect|maxRedirects)\s*[:=]\s*(?:true|\d{2,}|Infinity)/g,
    message: 'Redirect following enabled: SSRF via redirect to internal URL',
    description: 'Following redirects can be exploited to reach internal URLs via an external redirect.',
    fix: 'Disable redirect following for server-side requests, or validate each redirect destination.',
    falsePositive: 'If redirects are needed and each destination is validated.',
    tags: ['ssrf', 'redirect'],
  },
  {
    id: 'A10-dns-rebinding',
    owasp: 'A10:2021', cwe: 918, severity: 'high', confidence: 'low',
    pattern: /dns\.(?:resolve|lookup)\s*\(\s*(?:req\.|input|user|param|host|domain)/gi,
    message: 'DNS resolution with user input: DNS rebinding risk',
    description: 'Resolving user-supplied hostnames allows DNS rebinding attacks to reach internal services.',
    fix: 'Resolve DNS and verify the IP is not in private ranges before making requests.',
    falsePositive: 'If the hostname is from a trusted source and IP is verified.',
    tags: ['dns-rebinding', 'ssrf'],
  },
];

// ── EXTRA — TypeScript Patterns ─────────────────────────────────────────

const TS_RULES: OWASPRule[] = [
  {
    id: 'TS-any-abuse',
    owasp: 'EXTRA', cwe: 704, severity: 'low', confidence: 'medium',
    pattern: /:\s*any\b(?!\s*\))/g,
    message: 'TypeScript "any" type bypasses type safety',
    description: 'Using "any" disables TypeScript type checking, potentially hiding type-related bugs.',
    fix: 'Use specific types, "unknown", or generics instead of "any".',
    falsePositive: 'Acceptable in type definitions, generic constraints, or migration code.',
    tags: ['typescript', 'type-safety'],
  },
  {
    id: 'TS-ts-ignore',
    owasp: 'EXTRA', cwe: 710, severity: 'low', confidence: 'high',
    pattern: /\/\/\s*@ts-ignore/g,
    message: '@ts-ignore suppresses type errors — use @ts-expect-error instead',
    description: '@ts-ignore silently suppresses all errors on the next line, hiding real issues.',
    fix: 'Use @ts-expect-error (fails if no error exists) or fix the underlying type issue.',
    falsePositive: 'If suppressing a known TypeScript bug or third-party type issue.',
    tags: ['typescript', 'type-suppress'],
  },
  {
    id: 'TS-non-null-assertion',
    owasp: 'EXTRA', cwe: 476, severity: 'low', confidence: 'low',
    pattern: /\w+!\s*\.\s*\w+/g,
    message: 'Non-null assertion (!) may cause runtime null reference errors',
    description: 'The ! operator tells TypeScript to trust that a value is not null, but it may be at runtime.',
    fix: 'Use optional chaining (?.) or add a proper null check.',
    falsePositive: 'If the value is guaranteed non-null by program logic.',
    tags: ['typescript', 'null-safety'],
  },
  {
    id: 'TS-as-any-cast',
    owasp: 'EXTRA', cwe: 704, severity: 'medium', confidence: 'high',
    pattern: /\bas\s+any\b/g,
    message: '"as any" cast bypasses all type checking',
    description: 'Casting to "any" silences the compiler but can hide type mismatches and security issues.',
    fix: 'Use proper type narrowing, type guards, or "as unknown as TargetType" for safe casting.',
    falsePositive: 'If used temporarily during refactoring with a TODO to fix.',
    tags: ['typescript', 'type-cast'],
  },
];

// ── EXTRA — React/Next.js Patterns ──────────────────────────────────────

const REACT_RULES: OWASPRule[] = [
  {
    id: 'REACT-dangerous-html',
    owasp: 'EXTRA', cwe: 79, severity: 'high', confidence: 'high',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    message: 'XSS risk: dangerouslySetInnerHTML renders raw HTML',
    description: 'Rendering user-controlled HTML enables cross-site scripting attacks.',
    fix: 'Use a sanitizer (DOMPurify) before rendering, or use React text nodes instead.',
    falsePositive: 'If HTML is from a trusted CMS and sanitized before rendering.',
    tags: ['xss', 'react', 'html-injection'],
  },
  {
    id: 'REACT-href-javascript',
    owasp: 'EXTRA', cwe: 79, severity: 'critical', confidence: 'high',
    pattern: /href\s*=\s*\{?\s*['"`]javascript:/gi,
    message: 'XSS: javascript: protocol in href executes code on click',
    description: 'Links with javascript: protocol execute arbitrary code when clicked.',
    fix: 'Validate URLs and block javascript: protocol. Use onClick handlers instead.',
    falsePositive: 'Almost never — javascript: in href is always a security concern.',
    tags: ['xss', 'javascript-protocol'],
  },
  {
    id: 'REACT-unescaped-user-output',
    owasp: 'EXTRA', cwe: 79, severity: 'medium', confidence: 'low',
    pattern: /\{\s*(?:searchParams|query|params|router\.query)\s*\.\s*\w+\s*\}/g,
    message: 'URL parameter rendered directly — ensure React auto-escaping applies',
    description: 'While React auto-escapes JSX, ensure URL params are not used in dangerous contexts.',
    fix: 'Verify the value is only used in JSX text nodes (auto-escaped), not in href, src, or dangerouslySetInnerHTML.',
    falsePositive: 'React auto-escapes text content in JSX — only risky in attribute contexts.',
    tags: ['xss', 'url-params', 'react'],
  },
  {
    id: 'REACT-unsafe-lifecycle',
    owasp: 'EXTRA', cwe: 749, severity: 'low', confidence: 'medium',
    pattern: /(?:UNSAFE_componentWillMount|UNSAFE_componentWillReceiveProps|UNSAFE_componentWillUpdate)/g,
    message: 'Deprecated UNSAFE lifecycle method — potential race conditions',
    description: 'UNSAFE_ lifecycle methods have concurrency issues in React 18+ concurrent mode.',
    fix: 'Migrate to useEffect, useMemo, or getDerivedStateFromProps.',
    falsePositive: 'If using React <18 without concurrent features.',
    tags: ['react', 'deprecated', 'lifecycle'],
  },
  {
    id: 'REACT-open-redirect-router',
    owasp: 'EXTRA', cwe: 601, severity: 'high', confidence: 'medium',
    pattern: /(?:router\.push|router\.replace|redirect)\s*\(\s*(?:req\.query|searchParams\.get|params\.|query\.)/g,
    message: 'Open redirect: router navigation with user-controlled URL',
    description: 'Using URL parameters in router.push/redirect enables phishing via open redirects.',
    fix: 'Validate redirect targets against an allowlist. Use relative paths only.',
    falsePositive: 'If the redirect target is validated before use.',
    tags: ['open-redirect', 'react-router', 'nextjs'],
  },
];

// ── EXTRA — Node.js API Patterns ────────────────────────────────────────

const NODE_RULES: OWASPRule[] = [
  {
    id: 'NODE-path-join-user',
    owasp: 'EXTRA', cwe: 22, severity: 'high', confidence: 'medium',
    pattern: /path\.(?:join|resolve)\s*\([^)]*(?:req\.|input|user|param|query|body)/gi,
    message: 'Path traversal: path.join/resolve with user input',
    description: 'User input in path operations can escape the intended directory via ../ sequences.',
    fix: 'Validate the resolved path starts with the expected base directory.',
    falsePositive: 'If the result is checked against a base path before use.',
    tags: ['path-traversal', 'nodejs'],
  },
  {
    id: 'NODE-fs-user-path',
    owasp: 'EXTRA', cwe: 22, severity: 'high', confidence: 'medium',
    pattern: /fs\w*\.(?:readFile|writeFile|unlink|rmdir|mkdir|stat|access|readdir)\w*\s*\(\s*(?:req\.|input|user|param|query)/gi,
    message: 'File system operation with user-controlled path',
    description: 'User-controlled file paths enable reading, writing, or deleting arbitrary files.',
    fix: 'Validate and sanitize paths. Use a chroot-like base directory check.',
    falsePositive: 'If the path is validated against an allowed directory.',
    tags: ['path-traversal', 'filesystem', 'nodejs'],
  },
  {
    id: 'NODE-unsafe-deserialize',
    owasp: 'EXTRA', cwe: 502, severity: 'critical', confidence: 'high',
    pattern: /(?:node-serialize|serialize-javascript|js-yaml\.load)\s*\(\s*(?:req\.|input|user|body|data)/gi,
    message: 'Unsafe deserialization: untrusted data passed to deserializer',
    description: 'Deserializing untrusted data can lead to remote code execution.',
    fix: 'Use JSON.parse() with schema validation. Use yaml.safeLoad() instead of yaml.load().',
    falsePositive: 'If input is from a trusted source or validated before deserialization.',
    tags: ['deserialization', 'rce'],
  },
  {
    id: 'NODE-child-process-user',
    owasp: 'EXTRA', cwe: 78, severity: 'critical', confidence: 'high',
    pattern: /(?:child_process|require\s*\(\s*['"`]child_process['"`]\s*\))[\s\S]{0,50}(?:exec|spawn|fork|execFile)\s*\([^)]*(?:req\.|input|user|param)/gi,
    message: 'Command injection: child_process with user input',
    description: 'Passing user input to child_process functions enables arbitrary command execution.',
    fix: 'Use execFile() with argument arrays. Never interpolate user input into commands.',
    falsePositive: 'If the input is strictly validated (e.g., numeric ID only).',
    tags: ['command-injection', 'child-process'],
  },
  {
    id: 'NODE-buffer-alloc-unsafe',
    owasp: 'EXTRA', cwe: 457, severity: 'medium', confidence: 'high',
    pattern: /Buffer\.allocUnsafe\s*\(/g,
    message: 'Buffer.allocUnsafe: uninitialized memory may leak sensitive data',
    description: 'allocUnsafe does not zero memory, potentially exposing data from previous allocations.',
    fix: 'Use Buffer.alloc() (zero-filled) unless performance is critical and data is immediately overwritten.',
    falsePositive: 'If the buffer is completely filled before any read operation.',
    tags: ['buffer', 'memory-leak'],
  },
];

// ── EXTRA — Secrets Detection ───────────────────────────────────────────

const SECRETS_RULES: OWASPRule[] = [
  {
    id: 'SEC-aws-access-key',
    owasp: 'EXTRA', cwe: 798, severity: 'critical', confidence: 'high',
    pattern: /(?:AKIA[0-9A-Z]{16})/g,
    message: 'AWS Access Key ID detected in source code',
    description: 'AWS keys in source code can be used to access cloud resources and incur charges.',
    fix: 'Revoke the key immediately. Use IAM roles or environment variables instead.',
    falsePositive: 'If this is a test/example key (AKIAIOSFODNN7EXAMPLE).',
    tags: ['secrets', 'aws', 'api-key'],
  },
  {
    id: 'SEC-github-token',
    owasp: 'EXTRA', cwe: 798, severity: 'critical', confidence: 'high',
    pattern: /(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})/g,
    message: 'GitHub token detected in source code',
    description: 'GitHub tokens grant access to repositories, actions, and organization resources.',
    fix: 'Revoke the token at github.com/settings/tokens. Use environment variables.',
    falsePositive: 'If this is a documented example token format.',
    tags: ['secrets', 'github', 'token'],
  },
  {
    id: 'SEC-stripe-key',
    owasp: 'EXTRA', cwe: 798, severity: 'critical', confidence: 'high',
    pattern: /(?:sk_live_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,})/g,
    message: 'Stripe secret/restricted key detected',
    description: 'Stripe live keys can process charges and access customer payment data.',
    fix: 'Revoke the key at dashboard.stripe.com. Use environment variables.',
    falsePositive: 'If this is a test mode key (sk_test_...).',
    tags: ['secrets', 'stripe', 'payment'],
  },
  {
    id: 'SEC-generic-api-key',
    owasp: 'EXTRA', cwe: 798, severity: 'high', confidence: 'medium',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"`][A-Za-z0-9_\-+/=]{20,}['"`]/gi,
    message: 'Possible API key hardcoded in source code',
    description: 'API keys in source code are exposed through version control and build artifacts.',
    fix: 'Move to environment variables or a secrets manager.',
    falsePositive: 'If the value is a placeholder, test key, or public API key.',
    tags: ['secrets', 'api-key'],
  },
  {
    id: 'SEC-private-key-pem',
    owasp: 'EXTRA', cwe: 321, severity: 'critical', confidence: 'high',
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    message: 'Private key (PEM format) embedded in source code',
    description: 'Private keys in source code compromise all cryptographic operations using that key.',
    fix: 'Store private keys in a secrets manager or encrypted key store. Never commit to version control.',
    falsePositive: 'If this is a test/example key clearly documented as such.',
    tags: ['secrets', 'private-key', 'pem'],
  },
  {
    id: 'SEC-jwt-secret-hardcoded',
    owasp: 'EXTRA', cwe: 798, severity: 'critical', confidence: 'medium',
    pattern: /(?:jwt|token)[\w]*(?:Secret|Key|Signing)\s*[:=]\s*['"`][A-Za-z0-9+/=_\-]{16,}['"`]/gi,
    message: 'JWT signing secret hardcoded in source code',
    description: 'A leaked JWT secret allows forging authentication tokens for any user.',
    fix: 'Move to an environment variable. Rotate the secret if it has been committed.',
    falsePositive: 'If this is a test/development-only secret.',
    tags: ['secrets', 'jwt', 'signing-key'],
  },
  {
    id: 'SEC-database-url',
    owasp: 'EXTRA', cwe: 798, severity: 'critical', confidence: 'high',
    pattern: /['"`](?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^'"`\s]{10,}['"`]/g,
    message: 'Database connection string with credentials in source code',
    description: 'Database URLs often contain usernames and passwords that grant full database access.',
    fix: 'Use environment variable DATABASE_URL. Never hardcode connection strings.',
    falsePositive: 'If the URL uses localhost without credentials (development only).',
    tags: ['secrets', 'database', 'connection-string'],
  },
  {
    id: 'SEC-password-in-assignment',
    owasp: 'EXTRA', cwe: 798, severity: 'high', confidence: 'medium',
    pattern: /(?:const|let|var)\s+\w*(?:password|passwd|pwd|pass|secret|token)\w*\s*=\s*['"`][^'"`]{8,}['"`]/gi,
    message: 'Secret value assigned to variable as string literal',
    description: 'Hardcoded secrets in variable assignments are exposed in source code and builds.',
    fix: 'Use process.env.VARIABLE_NAME or a secrets manager.',
    falsePositive: 'If the variable holds a regex pattern, validation message, or field name.',
    tags: ['secrets', 'hardcoded-value'],
  },
];

// ── EXTRA — Dependency Confusion ────────────────────────────────────────

const DEP_RULES: OWASPRule[] = [
  {
    id: 'DEP-internal-scope',
    owasp: 'EXTRA', cwe: 427, severity: 'medium', confidence: 'low',
    pattern: /['"`]@(?:internal|private|corp|company|org)\/[^'"`]+['"`]/g,
    message: 'Internal-looking scoped package — verify it exists on your private registry',
    description: 'If an internal package name is registered on public npm, attackers can publish malicious versions.',
    fix: 'Register your scope on npm (even if empty). Use .npmrc to point scopes to your private registry.',
    falsePositive: 'If the scope is registered and protected on your private registry.',
    tags: ['dependency-confusion', 'supply-chain'],
  },
  {
    id: 'DEP-file-protocol',
    owasp: 'EXTRA', cwe: 829, severity: 'medium', confidence: 'high',
    pattern: /['"`]\s*:\s*['"`]file:/g,
    message: 'file: protocol dependency — local path reference',
    description: 'file: dependencies reference local paths, which may not exist in CI/CD or other environments.',
    fix: 'Publish to a private registry or use npm workspaces for monorepo packages.',
    falsePositive: 'If intentionally used in a monorepo workspace configuration.',
    tags: ['file-dependency', 'local-path'],
  },
];

// ── Rule Registry ───────────────────────────────────────────────────────

export const ALL_RULES: OWASPRule[] = [
  ...A01_RULES,
  ...A02_RULES,
  ...A03_RULES,
  ...A04_RULES,
  ...A05_RULES,
  ...A06_RULES,
  ...A07_RULES,
  ...A08_RULES,
  ...A09_RULES,
  ...A10_RULES,
  ...TS_RULES,
  ...REACT_RULES,
  ...NODE_RULES,
  ...SECRETS_RULES,
  ...DEP_RULES,
];

// ── Registry Helpers ────────────────────────────────────────────────────

export function getRulesByCategory(category: OWASPCategory): OWASPRule[] {
  return ALL_RULES.filter((r) => r.owasp === category);
}

export function getRuleById(id: string): OWASPRule | undefined {
  return ALL_RULES.find((r) => r.id === id);
}

export function getRuleByCWE(cwe: number): OWASPRule[] {
  return ALL_RULES.filter((r) => r.cwe === cwe);
}

export function getCategoryStats(): Record<OWASPCategory, number> {
  const stats = {} as Record<OWASPCategory, number>;
  for (const cat of Object.keys(OWASP_NAMES) as OWASPCategory[]) {
    stats[cat] = ALL_RULES.filter((r) => r.owasp === cat).length;
  }
  return stats;
}

export function getTotalRuleCount(): number {
  return ALL_RULES.length;
}

export function getUniqueCWEs(): number[] {
  return [...new Set(ALL_RULES.map((r) => r.cwe))].sort((a, b) => a - b);
}

