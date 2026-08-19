import type { SecurityFinding, Severity } from './finding.js';
import type { SkippedPath } from './file.js';

/** A rule that threw while examining a file. Reported, never fatal. */
export interface RuleError {
  readonly ruleId: string;
  readonly path: string;
  readonly message: string;
}

/** A suppression directive that could not be honoured. */
export interface SuppressionErrorReport {
  readonly path: string;
  readonly line: number;
  readonly message: string;
}

/** A finding that was suppressed, and why. */
export interface SuppressedFindingReport {
  readonly finding: SecurityFinding;
  readonly kind: 'rule-disabled' | 'baseline' | 'inline';
  readonly reason: string;
}

/** What the scan actually covered. */
export interface AuditStats {
  readonly filesDiscovered: number;
  /**
   * Files actually read and handed to at least one rule.
   *
   * Lower than `filesDiscovered` when a scan timed out, when files were
   * unreadable, or when no rule applied to them. It is a coverage number, so it
   * counts examination rather than intention.
   */
  readonly filesAnalysed: number;
  readonly filesParsed: number;
  readonly bytesRead: number;
  readonly rulesRun: number;
  readonly findingsBeforeDeduplication: number;
  readonly findingsSuppressed: number;
  readonly findingsBelowThreshold: number;
  /** Paths skipped by configuration, counted rather than listed. */
  readonly excludedByConfig: number;
  readonly notIncludedByConfig: number;
}

/**
 * The result of one scan.
 *
 * `truncated` and `timedOut` are part of the contract, not diagnostics. A report
 * that hit a limit covers less of the project than it appears to, and a consumer
 * that treats "no findings" as "nothing wrong" needs to be able to tell the
 * difference.
 */
export interface AuditReport {
  /** ISO 8601 timestamp of when the scan started. */
  readonly startedAt: string;
  readonly durationMs: number;
  /** Absolute project root. Machine-specific: reports that travel should not include it. */
  readonly root: string;
  readonly findings: readonly SecurityFinding[];
  readonly suppressed: readonly SuppressedFindingReport[];
  readonly skipped: readonly SkippedPath[];
  readonly ruleErrors: readonly RuleError[];
  readonly suppressionErrors: readonly SuppressionErrorReport[];
  readonly stats: AuditStats;
  /** True when a size, count or depth limit stopped the walk. */
  readonly truncated: boolean;
  /** True when the wall-clock budget ran out before every file was analysed. */
  readonly timedOut: boolean;
  /** Severity at which a CI run should fail, from configuration. */
  readonly failOn: Severity;
  /** Whether any reported finding meets {@link failOn}. The engine never exits a process. */
  readonly exceedsFailOn: boolean;
  /**
   * Whether AI analysis contributed to this report.
   *
   * Always `false` today, and stated in every report rather than assumed, so a
   * consumer can tell a deterministic result from an AI-assisted one without
   * knowing which version produced it (§28/§81).
   */
  readonly aiUsed: boolean;
}
