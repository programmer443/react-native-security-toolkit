import { meetsOrExceeds } from '../risk/riskEngine';
import type {
  CheckId,
  PolicyDecision,
  PolicyReason,
  PolicyReasonCode,
  SecurityCheckResult,
  SecurityConfidence,
  SecurityPolicy,
  SecurityReport,
} from '../types';

/**
 * Policy evaluation.
 *
 * The toolkit **returns a decision and does nothing else**. It will not block a
 * user, terminate the process, show UI, or make a network request. §73 of the
 * project brief is explicit about this, and it is the right design regardless:
 * an in-process kill switch is trivially bypassed by the attacker it is aimed
 * at, while reliably punishing developers and ordinary users who are not
 * attacking anyone.
 *
 * @see docs/runtime/security-policy.md
 */

const CONFIDENCE_ORDER: readonly SecurityConfidence[] = ['low', 'medium', 'high'];

/** Rules that map a detected check to a denial reason. */
const BLOCKING_RULES: ReadonlyArray<{
  readonly option: keyof SecurityPolicy;
  readonly checkId: CheckId;
  readonly code: PolicyReasonCode;
  readonly message: string;
}> = [
  {
    option: 'blockOnRoot',
    checkId: 'root',
    code: 'ROOT_DETECTED',
    message: 'Root indicators were detected on this device',
  },
  {
    option: 'blockOnJailbreak',
    checkId: 'jailbreak',
    code: 'JAILBREAK_DETECTED',
    message: 'Jailbreak indicators were detected on this device',
  },
  {
    option: 'blockOnDebugger',
    checkId: 'debugger',
    code: 'DEBUGGER_DETECTED',
    message: 'A debugger is attached to this application',
  },
  {
    option: 'blockOnHooking',
    checkId: 'hooks',
    code: 'HOOKING_DETECTED',
    message: 'Instrumentation indicators were detected in this process',
  },
  {
    option: 'blockOnIntegrityFailure',
    checkId: 'integrity',
    code: 'INTEGRITY_FAILED',
    message: 'Application integrity indicators were detected',
  },
];

/** Evaluates `policy` against `report`. */
export function evaluatePolicy(report: SecurityReport, policy: SecurityPolicy): PolicyDecision {
  const minimumConfidence = policy.minimumConfidence ?? 'low';
  const reasons: PolicyReason[] = [];

  for (const rule of BLOCKING_RULES) {
    if (policy[rule.option] !== true) {
      continue;
    }

    const result = report.checks[rule.checkId];
    if (result === undefined || result.status !== 'detected') {
      continue;
    }

    // A detection below the caller's confidence floor is recorded in the report
    // but does not block. This is the practical false-positive control: a
    // payment flow can demand corroborated evidence while still logging the rest.
    if (!meetsConfidence(result.confidence, minimumConfidence)) {
      continue;
    }

    reasons.push({
      code: rule.code,
      checkId: rule.checkId,
      signalIds: detectedSignalIds(result),
      message: rule.message,
    });
  }

  if (policy.minimumRiskLevel !== undefined) {
    if (meetsOrExceeds(report.risk.level, policy.minimumRiskLevel)) {
      reasons.push({
        code: 'RISK_LEVEL_EXCEEDED',
        signalIds: [],
        message:
          `Risk level ${report.risk.level} (score ${report.risk.score}) reached the configured ` +
          `threshold of ${policy.minimumRiskLevel}`,
      });
    }
  }

  if (policy.requireSecureHardware === true) {
    const result = report.checks.secureHardware;
    // An `unknown` result denies here, deliberately. A requirement that cannot be
    // shown to hold has not been met — treating "we could not tell" as
    // satisfaction would make the requirement meaningless.
    if (result === undefined || result.status !== 'secure') {
      reasons.push({
        code: 'SECURE_HARDWARE_UNAVAILABLE',
        checkId: 'secureHardware',
        signalIds: result === undefined ? [] : detectedSignalIds(result),
        message: 'Hardware-backed key storage could not be confirmed on this device',
      });
    }
  }

  if (policy.requireStrongBiometrics === true) {
    const result = report.checks.biometrics;
    if (result === undefined || result.status !== 'secure') {
      reasons.push({
        code: 'STRONG_BIOMETRICS_UNAVAILABLE',
        checkId: 'biometrics',
        signalIds: result === undefined ? [] : detectedSignalIds(result),
        message: 'Strong biometric authentication could not be confirmed on this device',
      });
    }
  }

  return Object.freeze({
    allowed: reasons.length === 0,
    reasons: Object.freeze(reasons),
    risk: report.risk,
    report,
    evaluatedAt: new Date().toISOString(),
  });
}

function meetsConfidence(actual: SecurityConfidence, minimum: SecurityConfidence): boolean {
  return CONFIDENCE_ORDER.indexOf(actual) >= CONFIDENCE_ORDER.indexOf(minimum);
}

function detectedSignalIds(result: SecurityCheckResult): readonly string[] {
  return Object.freeze(
    result.signals.filter((signal) => signal.detected).map((signal) => signal.id)
  );
}
