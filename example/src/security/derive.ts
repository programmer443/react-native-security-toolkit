/**
 * Read-only derivations over a report.
 *
 * Kept out of the components so the screens stay declarative, and so the counting
 * rules — which signals count as evidence, how checks are ordered — are stated
 * once. `indeterminate` is never folded into either "fired" or "clear": a probe
 * that could not run is not evidence of safety.
 */

import type {
  CheckId,
  RiskContributor,
  SecurityCheckResult,
  SecurityReport,
  SecurityStatus,
  SignalOutcome,
} from 'react-native-security-toolkit';
import { CHECK_ORDER } from './catalog';

export interface SignalTally {
  readonly fired: number;
  readonly inconclusive: number;
  readonly clear: number;
  readonly total: number;
}

export function tally(signals: readonly { readonly outcome: SignalOutcome }[]): SignalTally {
  let fired = 0;
  let inconclusive = 0;
  for (const signal of signals) {
    if (signal.outcome === 'detected') {
      fired += 1;
    } else if (signal.outcome === 'indeterminate') {
      inconclusive += 1;
    }
  }
  return {
    fired,
    inconclusive,
    clear: signals.length - fired - inconclusive,
    total: signals.length,
  };
}

/** Human summary of a check's signals, e.g. "2 fired · 1 inconclusive · 9 total". */
export function describeTally(counts: SignalTally): string {
  if (counts.total === 0) {
    return 'No signals reported';
  }
  const parts = [`${counts.fired} fired`];
  if (counts.inconclusive > 0) {
    parts.push(`${counts.inconclusive} inconclusive`);
  }
  parts.push(`${counts.total} total`);
  return parts.join(' · ');
}

/** Checks present in the report, in display order. */
export function orderedChecks(report: SecurityReport): readonly SecurityCheckResult[] {
  return CHECK_ORDER.map((id) => report.checks[id]).filter(
    (result): result is SecurityCheckResult => result !== undefined
  );
}

/**
 * Sort order for status. Anything demanding attention rises; `unavailable` sinks,
 * because on any given platform roughly half the checks are somebody else's.
 */
const STATUS_RANK: Readonly<Record<SecurityStatus, number>> = Object.freeze({
  detected: 0,
  unknown: 1,
  error: 2,
  secure: 3,
  unavailable: 4,
});

export function bySeverity(a: SecurityCheckResult, b: SecurityCheckResult): number {
  const byStatus = STATUS_RANK[a.status] - STATUS_RANK[b.status];
  if (byStatus !== 0) {
    return byStatus;
  }
  return CHECK_ORDER.indexOf(a.id) - CHECK_ORDER.indexOf(b.id);
}

export interface ReportSummary {
  readonly checksRun: number;
  readonly detected: number;
  readonly inconclusive: number;
  readonly unavailable: number;
  readonly signals: SignalTally;
}

export function summarise(report: SecurityReport): ReportSummary {
  const checks = orderedChecks(report);
  const signals = tally(checks.flatMap((check) => check.signals));
  return {
    checksRun: checks.filter((check) => check.status !== 'unavailable').length,
    detected: checks.filter((check) => check.status === 'detected').length,
    inconclusive: checks.filter((check) => check.status === 'unknown').length,
    unavailable: checks.filter((check) => check.status === 'unavailable').length,
    signals,
  };
}

/**
 * Points a check contributed to the score.
 *
 * Contributors are keyed by signal id for detections and by check id for
 * check-level adjustments, so both are matched here.
 */
export function pointsForCheck(report: SecurityReport, id: CheckId): number {
  const result = report.checks[id];
  if (result === undefined) {
    return 0;
  }
  const signalIds = new Set(result.signals.map((signal) => signal.id));
  return report.risk.contributors
    .filter((contributor) => contributor.source === id || signalIds.has(contributor.source))
    .reduce((sum, contributor) => sum + contributor.points, 0);
}

/** Contributors indexed by source, for annotating a signal row with its points. */
export function contributorIndex(report: SecurityReport): ReadonlyMap<string, RiskContributor> {
  return new Map(report.risk.contributors.map((contributor) => [contributor.source, contributor]));
}

/** Every signal in the report, tagged with the check that produced it. */
export interface TaggedSignal {
  readonly checkId: CheckId;
  readonly signal: SecurityCheckResult['signals'][number];
}

export function allSignals(report: SecurityReport): readonly TaggedSignal[] {
  return orderedChecks(report).flatMap((check) =>
    check.signals.map((signal) => ({ checkId: check.id, signal }))
  );
}

/** `14:32:07` — a wall-clock time, which is what a re-run needs to be legible. */
export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

/**
 * Formats a risk score.
 *
 * Scores are not always whole numbers — a signal's points are its base weight
 * times a confidence multiplier, so 15 × 0.7 lands on 10.5. Rounding for the
 * gauge and printing the raw value elsewhere would show the same score two ways
 * on two screens, which reads as a bug in the risk engine rather than a display
 * choice. One decimal, only when there is one.
 */
export function formatScore(score: number): string {
  const rounded = Math.round(score * 10) / 10;
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1);
}

/** Signed points, always with an explicit sign so a credit reads as a credit. */
export function formatPoints(points: number): string {
  return points > 0 ? `+${points}` : `${points}`;
}

/**
 * Renders a metadata value for display.
 *
 * Metadata arrives from native code as unknown-shaped JSON, so it is rendered
 * defensively rather than assumed to be a string. Nothing here can throw: a
 * detail screen must not be taken down by one odd value.
 */
export function formatMetadataValue(value: unknown): string {
  if (typeof value === 'string') {
    return value.length > 0 ? value : '""';
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (value === null || value === undefined) {
    return 'null';
  }
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return '[unserialisable]';
  }
}
