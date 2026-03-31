/**
 * ShieldPM — Security Posture Trending
 * Tracks dependency security posture over time to show improvement or regression.
 * Stores snapshots and generates trend data for dashboards.
 */

import { readFile, writeFile, readdir, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

// ── Types ────────────────────────────────────────────────────────────────

export interface PostureSnapshot {
  id: string;
  timestamp: string;
  projectName: string;
  metrics: PostureMetrics;
  packageScores: Record<string, number>;
  packageCount: number;
  highRiskPackages: string[];
}

export interface PostureMetrics {
  overallScore: number;
  averageRiskScore: number;
  maxRiskScore: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  licenseViolations: number;
  policyViolations: number;
  provenanceCoverage: number;
  manifestCoverage: number;
  sbomGenerated: boolean;
}

export interface PostureTrend {
  snapshots: PostureSnapshot[];
  trend: TrendDirection;
  changePercent: number;
  periodStart: string;
  periodEnd: string;
  improvements: string[];
  regressions: string[];
  summary: string;
}

export type TrendDirection = 'improving' | 'stable' | 'declining';

export interface PostureComparison {
  before: PostureSnapshot;
  after: PostureSnapshot;
  changes: PostureChange[];
  overallChange: TrendDirection;
  summary: string;
}

export interface PostureChange {
  metric: string;
  before: number;
  after: number;
  change: number;
  direction: 'improved' | 'unchanged' | 'regressed';
}

// ── Storage ─────────────────────────────────────────────────────────────

const POSTURE_DIR = '.shieldpm/posture';

function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

export async function saveSnapshot(
  projectDir: string,
  snapshot: PostureSnapshot
): Promise<string> {
  const dir = join(projectDir, POSTURE_DIR);
  await mkdir(dir, { recursive: true });

  const filename = `${snapshot.timestamp.slice(0, 10)}_${snapshot.id}.json`;
  const path = join(dir, filename);
  await writeFile(path, JSON.stringify(snapshot, null, 2) + '\n', 'utf-8');
  return path;
}

export async function loadSnapshots(
  projectDir: string,
  limit: number = 30
): Promise<PostureSnapshot[]> {
  const dir = join(projectDir, POSTURE_DIR);
  const snapshots: PostureSnapshot[] = [];

  try {
    const files = await readdir(dir);
    const jsonFiles = files
      .filter((f) => f.endsWith('.json'))
      .sort()
      .reverse()
      .slice(0, limit);

    for (const file of jsonFiles) {
      try {
        const raw = await readFile(join(dir, file), 'utf-8');
        snapshots.push(JSON.parse(raw) as PostureSnapshot);
      } catch { /* skip corrupt files */ }
    }
  } catch { /* no snapshots yet */ }

  return snapshots.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export async function getLatestSnapshot(projectDir: string): Promise<PostureSnapshot | null> {
  const snapshots = await loadSnapshots(projectDir, 1);
  return snapshots.length > 0 ? snapshots[snapshots.length - 1] : null;
}

// ── Snapshot Creation ───────────────────────────────────────────────────

export function createSnapshot(
  projectName: string,
  packageScores: Record<string, number>,
  metrics: Partial<PostureMetrics>
): PostureSnapshot {
  const scores = Object.values(packageScores);
  const avgScore = scores.length > 0
    ? scores.reduce((a, b) => a + b, 0) / scores.length
    : 0;
  const maxScore = scores.length > 0 ? Math.max(...scores) : 0;

  const fullMetrics: PostureMetrics = {
    overallScore: Math.round((10 - avgScore) * 10), // 0-100 where 100 is best
    averageRiskScore: Math.round(avgScore * 10) / 10,
    maxRiskScore: maxScore,
    totalFindings: 0,
    criticalFindings: 0,
    highFindings: 0,
    mediumFindings: 0,
    lowFindings: 0,
    licenseViolations: 0,
    policyViolations: 0,
    provenanceCoverage: 0,
    manifestCoverage: 0,
    sbomGenerated: false,
    ...metrics,
  };

  const highRiskPackages = Object.entries(packageScores)
    .filter(([, score]) => score >= 7)
    .map(([name]) => name);

  return {
    id: generateId(),
    timestamp: new Date().toISOString(),
    projectName,
    metrics: fullMetrics,
    packageScores,
    packageCount: scores.length,
    highRiskPackages,
  };
}

// ── Trend Analysis ──────────────────────────────────────────────────────

export function analyzeTrend(snapshots: PostureSnapshot[]): PostureTrend {
  if (snapshots.length === 0) {
    return {
      snapshots: [],
      trend: 'stable',
      changePercent: 0,
      periodStart: '',
      periodEnd: '',
      improvements: [],
      regressions: [],
      summary: 'No snapshots available for trend analysis',
    };
  }

  if (snapshots.length === 1) {
    return {
      snapshots,
      trend: 'stable',
      changePercent: 0,
      periodStart: snapshots[0].timestamp,
      periodEnd: snapshots[0].timestamp,
      improvements: [],
      regressions: [],
      summary: `Current posture score: ${snapshots[0].metrics.overallScore}/100`,
    };
  }

  const first = snapshots[0];
  const last = snapshots[snapshots.length - 1];
  const scoreDiff = last.metrics.overallScore - first.metrics.overallScore;
  const changePercent = first.metrics.overallScore > 0
    ? Math.round((scoreDiff / first.metrics.overallScore) * 100)
    : 0;

  const trend: TrendDirection = scoreDiff > 2 ? 'improving'
    : scoreDiff < -2 ? 'declining'
      : 'stable';

  const improvements: string[] = [];
  const regressions: string[] = [];

  // Compare first and last
  if (last.metrics.averageRiskScore < first.metrics.averageRiskScore) {
    improvements.push(`Average risk reduced: ${first.metrics.averageRiskScore} -> ${last.metrics.averageRiskScore}`);
  } else if (last.metrics.averageRiskScore > first.metrics.averageRiskScore) {
    regressions.push(`Average risk increased: ${first.metrics.averageRiskScore} -> ${last.metrics.averageRiskScore}`);
  }

  if (last.highRiskPackages.length < first.highRiskPackages.length) {
    improvements.push(`High-risk packages reduced: ${first.highRiskPackages.length} -> ${last.highRiskPackages.length}`);
  } else if (last.highRiskPackages.length > first.highRiskPackages.length) {
    regressions.push(`High-risk packages increased: ${first.highRiskPackages.length} -> ${last.highRiskPackages.length}`);
  }

  if (last.metrics.totalFindings < first.metrics.totalFindings) {
    improvements.push(`Total findings reduced: ${first.metrics.totalFindings} -> ${last.metrics.totalFindings}`);
  } else if (last.metrics.totalFindings > first.metrics.totalFindings) {
    regressions.push(`Total findings increased: ${first.metrics.totalFindings} -> ${last.metrics.totalFindings}`);
  }

  if (last.metrics.licenseViolations < first.metrics.licenseViolations) {
    improvements.push(`License violations reduced: ${first.metrics.licenseViolations} -> ${last.metrics.licenseViolations}`);
  }

  const trendEmoji = trend === 'improving' ? 'up' : trend === 'declining' ? 'down' : 'stable';
  const summary = `Posture ${trendEmoji}: ${first.metrics.overallScore}/100 -> ${last.metrics.overallScore}/100 (${changePercent >= 0 ? '+' : ''}${changePercent}%) over ${snapshots.length} snapshots`;

  return {
    snapshots,
    trend,
    changePercent,
    periodStart: first.timestamp,
    periodEnd: last.timestamp,
    improvements,
    regressions,
    summary,
  };
}

// ── Comparison ──────────────────────────────────────────────────────────

export function compareSnapshots(
  before: PostureSnapshot,
  after: PostureSnapshot
): PostureComparison {
  const changes: PostureChange[] = [];

  const metricPairs: Array<[string, keyof PostureMetrics]> = [
    ['Overall Score', 'overallScore'],
    ['Average Risk', 'averageRiskScore'],
    ['Max Risk', 'maxRiskScore'],
    ['Total Findings', 'totalFindings'],
    ['Critical Findings', 'criticalFindings'],
    ['High Findings', 'highFindings'],
    ['License Violations', 'licenseViolations'],
    ['Policy Violations', 'policyViolations'],
    ['Provenance Coverage', 'provenanceCoverage'],
    ['Manifest Coverage', 'manifestCoverage'],
  ];

  for (const [name, key] of metricPairs) {
    const bVal = before.metrics[key] as number;
    const aVal = after.metrics[key] as number;
    const change = aVal - bVal;

    // For "score" metrics, higher is better. For "findings/violations", lower is better
    const isScoreMetric = key === 'overallScore' || key === 'provenanceCoverage' || key === 'manifestCoverage';
    const direction: PostureChange['direction'] = change === 0 ? 'unchanged'
      : isScoreMetric
        ? (change > 0 ? 'improved' : 'regressed')
        : (change < 0 ? 'improved' : 'regressed');

    changes.push({ metric: name, before: bVal, after: aVal, change, direction });
  }

  const improved = changes.filter((c) => c.direction === 'improved').length;
  const regressed = changes.filter((c) => c.direction === 'regressed').length;

  const overallChange: TrendDirection = improved > regressed ? 'improving'
    : regressed > improved ? 'declining'
      : 'stable';

  const summary = `${improved} metrics improved, ${regressed} regressed, ${changes.filter((c) => c.direction === 'unchanged').length} unchanged`;

  return { before, after, changes, overallChange, summary };
}
