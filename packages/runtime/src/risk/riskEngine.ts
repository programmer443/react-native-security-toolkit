import {
  CONFIDENCE_MULTIPLIER,
  DEVELOPMENT_MODE_IGNORED_CHECKS,
  MAX_UNKNOWN_PENALTY,
  MITIGATION_CREDITS,
  RISK_LEVEL_THRESHOLDS,
  RISK_METHODOLOGY_VERSION,
  SIGNAL_WEIGHTS,
  UNKNOWN_CHECK_PENALTY,
  UNWEIGHTED_SIGNAL_POINTS,
} from './weights';
import type {
  CheckId,
  RiskContributor,
  RiskLevel,
  SecurityCheckResult,
  SecurityRisk,
} from '../types';

/**
 * Deterministic risk scoring.
 *
 * Three properties this function is required to have, all of them tested:
 *
 * 1. **Deterministic.** The same results always produce the same score. No
 *    randomness, no clock, no network, no AI. §23 of the project brief forbids
 *    AI from influencing runtime scores, and it cannot here — this module has no
 *    dependency that could.
 * 2. **Explainable.** Every contributor is returned. A bare number is never
 *    emitted, because a score nobody can account for is a score nobody should
 *    act on.
 * 3. **Versioned.** Weights live in one table stamped with a methodology
 *    version, so a score can be traced to the rules that produced it.
 *
 * @see docs/runtime/risk-scoring.md
 */

export interface RiskEvaluationOptions {
  /** Suppresses debugger, emulator and simulator contributions. */
  readonly developmentMode: boolean;
}

/**
 * Scores a set of check results.
 *
 * @param checks results by check id. Absent checks contribute nothing — a check
 *   the platform does not implement is not evidence of anything.
 */
export function evaluateRisk(
  checks: Readonly<Partial<Record<CheckId, SecurityCheckResult>>>,
  options: RiskEvaluationOptions
): SecurityRisk {
  const contributors: RiskContributor[] = [];
  let unknownPenalty = 0;

  for (const result of Object.values(checks)) {
    if (result === undefined) {
      continue;
    }

    const ignored = options.developmentMode && DEVELOPMENT_MODE_IGNORED_CHECKS.includes(result.id);

    if (result.status === 'detected' && !ignored) {
      for (const signal of result.signals) {
        if (!signal.detected) {
          continue;
        }
        const basePoints = SIGNAL_WEIGHTS[signal.id] ?? UNWEIGHTED_SIGNAL_POINTS;
        const points = round(basePoints * CONFIDENCE_MULTIPLIER[signal.confidence]);
        if (points === 0) {
          continue;
        }
        contributors.push({
          source: signal.id,
          points,
          reason: signal.description,
        });
      }
    }

    // Uncertainty is not compromise, but it is not safety either. Capped so a
    // device with unreadable probes cannot reach `critical` on ignorance alone.
    if (result.status === 'unknown' && unknownPenalty < MAX_UNKNOWN_PENALTY) {
      const points = Math.min(UNKNOWN_CHECK_PENALTY, MAX_UNKNOWN_PENALTY - unknownPenalty);
      unknownPenalty += points;
      contributors.push({
        source: result.id,
        points,
        reason: `The ${result.id} check could not reach a verdict`,
      });
    }

    // Credit only for a check that actually completed. `unknown` has
    // demonstrated nothing and earns nothing.
    if (result.status === 'secure') {
      const credit = MITIGATION_CREDITS[result.id];
      if (credit !== undefined) {
        contributors.push({
          source: result.id,
          points: -credit,
          reason: `The ${result.id} check completed with no indicators`,
        });
      }
    }
  }

  const total = contributors.reduce((sum, contributor) => sum + contributor.points, 0);
  const score = clamp(round(total), 0, 100);

  return Object.freeze({
    score,
    level: levelFor(score),
    // Largest influences first: whoever reads this wants the headline, not the
    // rounding errors.
    contributors: Object.freeze(
      [...contributors].sort((a, b) => Math.abs(b.points) - Math.abs(a.points))
    ),
    methodologyVersion: RISK_METHODOLOGY_VERSION,
  });
}

/** The risk band a score falls into. */
export function levelFor(score: number): RiskLevel {
  for (const threshold of RISK_LEVEL_THRESHOLDS) {
    if (score >= threshold.minimum) {
      return threshold.level;
    }
  }
  return 'minimal';
}

/** Ordering for comparing risk levels. */
export const RISK_LEVEL_ORDER: readonly RiskLevel[] = Object.freeze([
  'minimal',
  'low',
  'medium',
  'high',
  'critical',
]);

/** Whether `level` is at or above `threshold`. */
export function meetsOrExceeds(level: RiskLevel, threshold: RiskLevel): boolean {
  return RISK_LEVEL_ORDER.indexOf(level) >= RISK_LEVEL_ORDER.indexOf(threshold);
}

/** One decimal place, so scores stay reproducible across platforms. */
function round(value: number): number {
  return Math.round(value * 10) / 10;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}
