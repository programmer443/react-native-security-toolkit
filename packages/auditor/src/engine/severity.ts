import { isExamplePath, isFixturePath, isTestPath } from '../classification/classify.js';
import { matchesAnyGlob } from '../util/glob.js';
import type { RuleOverride } from '../types/config.js';
import type { Severity } from '../types/finding.js';

/**
 * Severity, computed rather than declared.
 *
 * A rule states a base severity for the problem it detects. The same problem is
 * not equally serious everywhere: a hardcoded key in `__fixtures__` is test
 * data, and one in `src/api/client.ts` is an incident. The brief calls out the
 * "flag every AsyncStorage call" failure mode three separate times, and this is
 * where it is prevented.
 *
 * Every adjustment is **recorded on the finding**, never applied silently. A
 * downgraded finding that cannot be traced back to the rule that downgraded it
 * is indistinguishable from a missed one.
 */

const ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Negative when `left` is less severe than `right`. */
export function compareSeverity(left: Severity, right: Severity): number {
  return ORDER.indexOf(left) - ORDER.indexOf(right);
}

/** Whether a severity meets or exceeds a threshold. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return compareSeverity(severity, threshold) >= 0;
}

/** The more severe of two severities. */
export function maxSeverity(left: Severity, right: Severity): Severity {
  return compareSeverity(left, right) >= 0 ? left : right;
}

/** Moves a severity down the scale, stopping at `info`. */
function downgrade(severity: Severity, steps: number): Severity {
  const index = ORDER.indexOf(severity);
  return ORDER[Math.max(0, index - steps)] ?? 'info';
}

export interface SeverityDecision {
  readonly severity: Severity;
  readonly adjustment?: {
    readonly from: Severity;
    readonly to: Severity;
    readonly reason: string;
  };
}

/**
 * Resolves the severity of one finding.
 *
 * A configuration override is **final**: an explicit decision by the project
 * author outranks the engine's contextual judgement, and second-guessing it
 * would make the override untrustworthy.
 */
export function resolveSeverity(
  base: Severity,
  filePath: string,
  ruleId: string,
  overrides: readonly RuleOverride[]
): SeverityDecision {
  const override = overrides.find(
    (candidate) =>
      candidate.rule === ruleId &&
      candidate.severity !== undefined &&
      (candidate.paths === undefined || matchesAnyGlob(filePath, candidate.paths))
  );

  if (override?.severity !== undefined) {
    if (override.severity === base) {
      return { severity: base };
    }
    return {
      severity: override.severity,
      adjustment: { from: base, to: override.severity, reason: 'configuration override' },
    };
  }

  const context = contextAdjustment(filePath);
  if (context === undefined) {
    return { severity: base };
  }

  const adjusted = downgrade(base, context.steps);
  if (adjusted === base) {
    return { severity: base };
  }

  return {
    severity: adjusted,
    adjustment: { from: base, to: adjusted, reason: context.reason },
  };
}

/**
 * How far a path's context lowers a finding's severity.
 *
 * Fixtures fall furthest because deliberately insecure code is the *point* of a
 * fixture — this project's own test suite is full of it. Nothing is dropped
 * outright: a real credential committed to a fixture directory is still a real
 * credential, and `info` keeps it visible.
 */
function contextAdjustment(filePath: string): { steps: number; reason: string } | undefined {
  if (isFixturePath(filePath)) {
    return { steps: 2, reason: 'file is a fixture, mock or snapshot' };
  }
  if (isTestPath(filePath)) {
    return { steps: 1, reason: 'file is test code' };
  }
  if (isExamplePath(filePath)) {
    return { steps: 1, reason: 'file is part of an example or demo application' };
  }
  return undefined;
}
