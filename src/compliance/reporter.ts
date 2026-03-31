/**
 * ShieldPM — Compliance Reporter
 * Generates compliance reports aligned with SOC2, ISO 27001, PCI-DSS,
 * and EO 14028 frameworks. Maps ShieldPM findings to control requirements.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { RiskReport, Finding } from '../analyzer/static.js';
import type { LicenseReport } from '../license/compliance.js';
import type { SBOMDocument } from '../sbom/generator.js';
import type { PolicyEvaluation } from '../policy/engine.js';

// ── Types ────────────────────────────────────────────────────────────────

export type ComplianceFramework = 'soc2' | 'iso27001' | 'pci-dss' | 'eo14028' | 'nist-ssdf';

export type ControlStatus = 'met' | 'partial' | 'not-met' | 'not-applicable';

export interface ControlMapping {
  controlId: string;
  controlName: string;
  framework: ComplianceFramework;
  description: string;
  status: ControlStatus;
  evidence: string[];
  gaps: string[];
  recommendations: string[];
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  frameworkName: string;
  generatedAt: string;
  projectName: string;
  controls: ControlMapping[];
  summary: {
    totalControls: number;
    met: number;
    partial: number;
    notMet: number;
    notApplicable: number;
    complianceScore: number;
  };
}

export interface ComplianceInput {
  riskReports: Map<string, RiskReport>;
  licenseReport?: LicenseReport;
  sbom?: SBOMDocument;
  policyEvaluation?: PolicyEvaluation[];
  hasManifest: boolean;
  hasLockfile: boolean;
  hasSBOM: boolean;
  hasPolicy: boolean;
}

// ── SOC2 Controls ───────────────────────────────────────────────────────

function generateSOC2Controls(input: ComplianceInput): ControlMapping[] {
  const controls: ControlMapping[] = [];
  const totalPkgs = input.riskReports.size;
  const highRiskPkgs = [...input.riskReports.values()].filter((r) => r.score >= 7).length;
  const medRiskPkgs = [...input.riskReports.values()].filter((r) => r.score >= 4 && r.score < 7).length;

  // CC6.1 — Logical Access Controls
  controls.push({
    controlId: 'CC6.1',
    controlName: 'Logical Access Controls',
    framework: 'soc2',
    description: 'The entity implements logical access security measures to protect against unauthorized access',
    status: input.hasManifest ? 'met' : 'partial',
    evidence: [
      ...(input.hasManifest ? ['Permission manifest (shieldpm.json) enforces least-privilege per package'] : []),
      `${totalPkgs} packages scanned for unauthorized access patterns`,
    ],
    gaps: input.hasManifest ? [] : ['No permission manifest found — packages have unrestricted access'],
    recommendations: input.hasManifest ? [] : ['Run: shieldpm manifest generate'],
  });

  // CC6.6 — System Boundaries
  controls.push({
    controlId: 'CC6.6',
    controlName: 'System Boundary Protection',
    framework: 'soc2',
    description: 'The entity implements controls to restrict access to system boundaries',
    status: highRiskPkgs === 0 ? 'met' : highRiskPkgs <= 2 ? 'partial' : 'not-met',
    evidence: [
      `${totalPkgs} dependencies analyzed for boundary violations`,
      `${highRiskPkgs} high-risk packages detected`,
      `Static analysis covers network, filesystem, and process spawning patterns`,
    ],
    gaps: highRiskPkgs > 0 ? [`${highRiskPkgs} packages with high risk scores need review`] : [],
    recommendations: highRiskPkgs > 0 ? ['Review and remediate high-risk packages', 'Add reviewed packages to permission manifest'] : [],
  });

  // CC7.1 — Vulnerability Management
  controls.push({
    controlId: 'CC7.1',
    controlName: 'Vulnerability Management',
    framework: 'soc2',
    description: 'The entity detects and monitors for vulnerabilities in system components',
    status: 'met',
    evidence: [
      `Static analysis engine scans ${totalPkgs} packages with 30+ detection rules`,
      'Behavioral fingerprinting tracks package changes between versions',
      'Typosquatting detection prevents supply chain attacks',
      ...(input.hasSBOM ? ['SBOM generated for dependency transparency'] : []),
    ],
    gaps: [],
    recommendations: ['Consider adding CVE database integration for known vulnerability detection'],
  });

  // CC7.2 — Change Detection
  controls.push({
    controlId: 'CC7.2',
    controlName: 'Change Detection & Monitoring',
    framework: 'soc2',
    description: 'The entity monitors system components for changes that could affect security',
    status: input.hasLockfile ? 'met' : 'partial',
    evidence: [
      'Dependency diff engine detects changes in package-lock.json',
      'Behavioral profiling creates SHA-256 fingerprints of package behavior',
      ...(input.hasLockfile ? ['Lock file present — dependency versions are pinned'] : []),
    ],
    gaps: input.hasLockfile ? [] : ['No package-lock.json found — dependency versions may drift'],
    recommendations: input.hasLockfile ? [] : ['Commit package-lock.json to version control'],
  });

  // CC8.1 — Software Development
  controls.push({
    controlId: 'CC8.1',
    controlName: 'Secure Software Development',
    framework: 'soc2',
    description: 'The entity applies secure development practices',
    status: input.hasPolicy ? 'met' : 'partial',
    evidence: [
      'Sandboxed execution of install scripts prevents code execution during installation',
      `${totalPkgs} packages scanned before deployment`,
      ...(input.hasPolicy ? ['Security policy enforced via policy-as-code engine'] : []),
    ],
    gaps: input.hasPolicy ? [] : ['No security policy defined'],
    recommendations: input.hasPolicy ? [] : ['Run: shieldpm policy init'],
  });

  return controls;
}

// ── ISO 27001 Controls ──────────────────────────────────────────────────

function generateISO27001Controls(input: ComplianceInput): ControlMapping[] {
  const controls: ControlMapping[] = [];
  const totalPkgs = input.riskReports.size;
  const licenseViolations = input.licenseReport?.violations.length ?? 0;

  // A.12.6.1 — Management of Technical Vulnerabilities
  controls.push({
    controlId: 'A.12.6.1',
    controlName: 'Management of Technical Vulnerabilities',
    framework: 'iso27001',
    description: 'Information about technical vulnerabilities shall be obtained and evaluated',
    status: 'met',
    evidence: [
      `${totalPkgs} third-party packages analyzed for vulnerabilities`,
      'Static analysis covers code execution, network access, filesystem access, obfuscation',
      'Typosquatting detection protects against dependency confusion',
    ],
    gaps: [],
    recommendations: [],
  });

  // A.14.1.2 — Securing Application Services
  controls.push({
    controlId: 'A.14.1.2',
    controlName: 'Securing Application Services',
    framework: 'iso27001',
    description: 'Information involved in application services shall be protected',
    status: input.hasManifest ? 'met' : 'partial',
    evidence: [
      ...(input.hasManifest ? ['Permission manifest restricts package capabilities'] : []),
      'Sandbox execution isolates install scripts from system resources',
    ],
    gaps: input.hasManifest ? [] : ['No permission manifest — packages have unrestricted capabilities'],
    recommendations: input.hasManifest ? [] : ['Generate and enforce permission manifest'],
  });

  // A.14.2.1 — Secure Development Policy
  controls.push({
    controlId: 'A.14.2.1',
    controlName: 'Secure Development Policy',
    framework: 'iso27001',
    description: 'Rules for the development of software and systems shall be established',
    status: input.hasPolicy ? 'met' : 'partial',
    evidence: [
      ...(input.hasPolicy ? ['Policy-as-code engine enforces development security rules'] : []),
      'Package risk scoring provides quantitative security assessment',
    ],
    gaps: input.hasPolicy ? [] : ['No formal security policy for dependency management'],
    recommendations: input.hasPolicy ? [] : ['Define and enforce security policy'],
  });

  // A.18.1.2 — Intellectual Property Rights
  controls.push({
    controlId: 'A.18.1.2',
    controlName: 'Intellectual Property Rights',
    framework: 'iso27001',
    description: 'Appropriate procedures shall ensure compliance with IPR requirements',
    status: licenseViolations === 0 ? 'met' : 'not-met',
    evidence: [
      `License compliance scan completed for ${totalPkgs} packages`,
      ...(input.licenseReport ? [
        `${input.licenseReport.summary.permissive} permissive, ${input.licenseReport.summary.copyleft} copyleft, ${input.licenseReport.summary.unknown} unknown`,
      ] : []),
    ],
    gaps: licenseViolations > 0 ? [`${licenseViolations} license compliance violations found`] : [],
    recommendations: licenseViolations > 0 ? ['Review and resolve license violations', 'Consider replacing packages with incompatible licenses'] : [],
  });

  // A.15.1.1 — Supply Chain Security
  controls.push({
    controlId: 'A.15.1.1',
    controlName: 'Information Security in Supplier Relationships',
    framework: 'iso27001',
    description: 'Information security requirements for mitigating risks from suppliers',
    status: input.hasSBOM ? 'met' : 'partial',
    evidence: [
      `${totalPkgs} third-party components inventoried and analyzed`,
      ...(input.hasSBOM ? ['SBOM generated for full supply chain transparency'] : []),
      'Behavioral fingerprinting tracks component changes',
    ],
    gaps: input.hasSBOM ? [] : ['No SBOM generated for supply chain documentation'],
    recommendations: input.hasSBOM ? [] : ['Generate SBOM: shieldpm sbom --format cyclonedx'],
  });

  return controls;
}

// ── PCI-DSS Controls ────────────────────────────────────────────────────

function generatePCIDSSControls(input: ComplianceInput): ControlMapping[] {
  const controls: ControlMapping[] = [];
  const totalPkgs = input.riskReports.size;

  // 6.3.2 — Software Inventory
  controls.push({
    controlId: '6.3.2',
    controlName: 'Software Inventory',
    framework: 'pci-dss',
    description: 'An inventory of bespoke and custom software, and third-party software components',
    status: input.hasSBOM ? 'met' : 'partial',
    evidence: [
      `${totalPkgs} third-party components identified`,
      ...(input.hasSBOM ? ['SBOM generated with full component inventory including versions and licenses'] : []),
    ],
    gaps: input.hasSBOM ? [] : ['Formal SBOM not generated'],
    recommendations: input.hasSBOM ? [] : ['Generate SBOM for PCI compliance'],
  });

  // 6.2.4 — Software Engineering Security
  controls.push({
    controlId: '6.2.4',
    controlName: 'Software Engineering Techniques',
    framework: 'pci-dss',
    description: 'Software engineering techniques prevent or mitigate common software attacks',
    status: 'met',
    evidence: [
      'Static analysis detects code injection, XSS, and command injection patterns',
      'Prototype pollution detection prevents object manipulation attacks',
      'Obfuscation detection identifies hidden malicious code',
    ],
    gaps: [],
    recommendations: [],
  });

  // 6.3.1 — Vulnerability Identification
  controls.push({
    controlId: '6.3.1',
    controlName: 'Security Vulnerability Identification',
    framework: 'pci-dss',
    description: 'Security vulnerabilities are identified and managed',
    status: 'met',
    evidence: [
      `${totalPkgs} packages scanned with 30+ security rules`,
      'Risk scoring system (0-10) quantifies package security posture',
      'Dependency diff detects unexpected changes in the supply chain',
    ],
    gaps: [],
    recommendations: ['Integrate CVE database for known vulnerability scanning'],
  });

  return controls;
}

// ── EO 14028 Controls ───────────────────────────────────────────────────

function generateEO14028Controls(input: ComplianceInput): ControlMapping[] {
  const controls: ControlMapping[] = [];

  // Section 4(e) — SBOM
  controls.push({
    controlId: 'EO-4e',
    controlName: 'Software Bill of Materials',
    framework: 'eo14028',
    description: 'Providing a purchaser an SBOM for each product',
    status: input.hasSBOM ? 'met' : 'not-met',
    evidence: input.hasSBOM
      ? ['SBOM generated in CycloneDX/SPDX format', `${input.sbom?.totalComponents ?? 0} components documented`]
      : [],
    gaps: input.hasSBOM ? [] : ['No SBOM generated — required by Executive Order 14028'],
    recommendations: input.hasSBOM ? [] : ['Generate SBOM immediately: shieldpm sbom'],
  });

  // Section 4(e) — Automated Tools
  controls.push({
    controlId: 'EO-4e-tools',
    controlName: 'Automated Security Tools',
    framework: 'eo14028',
    description: 'Employing automated tools to maintain trusted source code supply chains',
    status: 'met',
    evidence: [
      'ShieldPM provides automated static analysis of all dependencies',
      'Behavioral fingerprinting detects supply chain tampering',
      'Typosquatting detection prevents dependency confusion attacks',
      'Sandboxed execution isolates untrusted code',
    ],
    gaps: [],
    recommendations: [],
  });

  // Section 4(i) — Supply Chain Security
  controls.push({
    controlId: 'EO-4i',
    controlName: 'Software Supply Chain Security',
    framework: 'eo14028',
    description: 'Ensuring and attesting to the integrity of open-source software',
    status: input.hasManifest && input.hasPolicy ? 'met' : 'partial',
    evidence: [
      'Package integrity verified via behavioral fingerprinting',
      ...(input.hasManifest ? ['Permission manifest enforces least-privilege'] : []),
      ...(input.hasPolicy ? ['Security policy defines acceptable risk thresholds'] : []),
    ],
    gaps: [
      ...(!input.hasManifest ? ['Missing permission manifest'] : []),
      ...(!input.hasPolicy ? ['Missing security policy'] : []),
    ],
    recommendations: [
      ...(!input.hasManifest ? ['Generate permission manifest'] : []),
      ...(!input.hasPolicy ? ['Initialize security policy'] : []),
    ],
  });

  return controls;
}

// ── Report Generation ───────────────────────────────────────────────────

const FRAMEWORK_NAMES: Record<ComplianceFramework, string> = {
  'soc2': 'SOC 2 Type II',
  'iso27001': 'ISO/IEC 27001:2022',
  'pci-dss': 'PCI DSS v4.0',
  'eo14028': 'Executive Order 14028',
  'nist-ssdf': 'NIST SSDF v1.1',
};

export function generateComplianceReport(
  framework: ComplianceFramework,
  input: ComplianceInput,
  projectName: string = 'unknown'
): ComplianceReport {
  let controls: ControlMapping[];

  switch (framework) {
    case 'soc2':
      controls = generateSOC2Controls(input);
      break;
    case 'iso27001':
      controls = generateISO27001Controls(input);
      break;
    case 'pci-dss':
      controls = generatePCIDSSControls(input);
      break;
    case 'eo14028':
      controls = generateEO14028Controls(input);
      break;
    case 'nist-ssdf':
      controls = generateEO14028Controls(input); // Closely related
      break;
    default:
      controls = [];
  }

  const met = controls.filter((c) => c.status === 'met').length;
  const partial = controls.filter((c) => c.status === 'partial').length;
  const notMet = controls.filter((c) => c.status === 'not-met').length;
  const notApplicable = controls.filter((c) => c.status === 'not-applicable').length;
  const total = controls.length;
  const complianceScore = total > 0
    ? Math.round(((met + partial * 0.5) / (total - notApplicable)) * 100)
    : 0;

  return {
    framework,
    frameworkName: FRAMEWORK_NAMES[framework],
    generatedAt: new Date().toISOString(),
    projectName,
    controls,
    summary: { totalControls: total, met, partial, notMet, notApplicable, complianceScore },
  };
}

export function generateAllComplianceReports(
  input: ComplianceInput,
  projectName?: string
): ComplianceReport[] {
  const frameworks: ComplianceFramework[] = ['soc2', 'iso27001', 'pci-dss', 'eo14028'];
  return frameworks.map((fw) => generateComplianceReport(fw, input, projectName));
}
