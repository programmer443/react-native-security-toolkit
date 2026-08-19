import type { AuditReport } from '../types/report.js';
import type { Severity } from '../types/finding.js';

/**
 * Reporters turn one audit report into one string.
 *
 * Pure functions, deliberately: a reporter that writes files or talks to a
 * network is a reporter that cannot be tested, and output formats are exactly
 * the kind of thing that rots without tests. Writing bytes anywhere is the
 * caller's job.
 */
export interface Reporter {
  /** Name used to select the format, e.g. `sarif`. */
  readonly name: ReportFormat;
  /** File extension, without the dot. */
  readonly extension: string;
  /** Media type, for callers that publish the output. */
  readonly contentType: string;
  render(report: AuditReport, options?: ReportOptions): string;
}

export type ReportFormat = 'console' | 'json' | 'markdown' | 'html' | 'sarif';

export interface ReportOptions {
  /**
   * Include the absolute project root in the output.
   *
   * Off by default. A report is an artefact that travels — into CI logs, pull
   * requests, issue trackers — and `/Users/someone/work/client-project` is both
   * noise and, occasionally, something the author would rather not publish.
   */
  readonly includeRoot?: boolean;
  /** Tool version recorded in the output. */
  readonly toolVersion?: string;
  /** ANSI colour, for the console reporter. Off unless the caller asks. */
  readonly colour?: boolean;
  /** Injectable clock, so generated output is deterministic under test. */
  readonly now?: () => Date;
}

/** Name and version recorded in machine-readable output. */
export const TOOL_NAME = 'rn-security-auditor';
export const TOOL_INFORMATION_URI =
  'https://github.com/programmer443/react-native-security-toolkit';

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Counts by severity, in descending order of severity. */
export function countBySeverity(report: AuditReport): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of report.findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

/**
 * A one-line statement of coverage, or `undefined` when the scan was complete.
 *
 * Every reporter prints this. "No findings" from a scan that stopped after 200
 * of 20,000 files means nothing, and a reader has no way to tell unless the
 * report says so.
 */
export function coverageWarning(report: AuditReport): string | undefined {
  const reasons: string[] = [];
  if (report.truncated) {
    reasons.push('a size, count or depth limit stopped the walk');
  }
  if (report.timedOut) {
    reasons.push('the time budget ran out');
  }
  if (reasons.length === 0) {
    return undefined;
  }
  return `INCOMPLETE SCAN: ${reasons.join('; ')}. Findings cover only what was read.`;
}

/** ISO 8601 timestamp for generated output. */
export function timestamp(options: ReportOptions | undefined): string {
  return (options?.now?.() ?? new Date()).toISOString();
}
