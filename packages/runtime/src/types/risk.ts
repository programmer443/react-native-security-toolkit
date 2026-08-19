import type { CheckId, Platform, SecurityCheckResult } from './result';

/**
 * Risk and policy types.
 *
 * @see docs/runtime/risk-scoring.md
 * @see docs/runtime/security-policy.md
 */

/** Overall risk band. */
export type RiskLevel = 'minimal' | 'low' | 'medium' | 'high' | 'critical';

/**
 * One line of the arithmetic behind a score.
 *
 * Every contributor is returned, so a score can always be explained. A bare
 * number is never emitted.
 */
export interface RiskContributor {
  /** Signal that produced it, or the check id for check-level adjustments. */
  readonly source: string;
  /** Signed points. Positive increases risk; negative is a mitigation credit. */
  readonly points: number;
  /** Human-readable explanation of why this contributed. */
  readonly reason: string;
}

/** Deterministic risk assessment. */
export interface SecurityRisk {
  /** 0–100, clamped. */
  readonly score: number;
  readonly level: RiskLevel;
  /** Every contributor, ordered by descending absolute weight. */
  readonly contributors: readonly RiskContributor[];
  /** Version of the weights and rules that produced this score. */
  readonly methodologyVersion: string;
}

/** Aggregate result of {@link SecurityToolkit.checkAll}. */
export interface SecurityReport {
  /**
   * Convenience flag: `true` when {@link SecurityRisk.level} is `high` or
   * `critical`.
   *
   * A derived summary, **not** an assertion that the device is definitely
   * compromised. Runtime checks cannot establish that. Read `risk.contributors`
   * before acting on it.
   */
  readonly compromised: boolean;
  readonly risk: SecurityRisk;
  readonly platform: Platform;
  /**
   * Results by check id.
   *
   * Checks the platform does not implement are **absent**, not present with an
   * error. Absence is the honest encoding of "this check does not exist here".
   */
  readonly checks: Readonly<Partial<Record<CheckId, SecurityCheckResult>>>;
  /** Version of the native engine that produced these results. */
  readonly engineVersion: string;
  /** Wall-clock duration of the whole aggregate check, in milliseconds. */
  readonly durationMs: number;
  readonly checkedAt: string;
}

/**
 * An application-defined policy.
 *
 * Every field is optional; an empty policy allows everything. The toolkit
 * evaluates a policy and returns a decision — it never enforces one.
 */
export interface SecurityPolicy {
  readonly blockOnRoot?: boolean;
  readonly blockOnJailbreak?: boolean;
  readonly blockOnDebugger?: boolean;
  readonly blockOnHooking?: boolean;
  readonly blockOnIntegrityFailure?: boolean;
  /** Block when risk reaches this level or above. */
  readonly minimumRiskLevel?: RiskLevel;
  /** Require hardware-backed key storage. */
  readonly requireSecureHardware?: boolean;
  /** Require usable strong biometric authentication. */
  readonly requireStrongBiometrics?: boolean;
  /**
   * Ignore detections weaker than this.
   *
   * The practical false-positive control: require corroborated `high`-confidence
   * evidence before blocking a payment, while still logging weaker signals.
   *
   * @defaultValue `'low'`
   */
  readonly minimumConfidence?: 'low' | 'medium' | 'high';
}

/** Machine-readable reason a policy denied. */
export type PolicyReasonCode =
  | 'ROOT_DETECTED'
  | 'JAILBREAK_DETECTED'
  | 'DEBUGGER_DETECTED'
  | 'HOOKING_DETECTED'
  | 'INTEGRITY_FAILED'
  | 'RISK_LEVEL_EXCEEDED'
  | 'SECURE_HARDWARE_UNAVAILABLE'
  | 'STRONG_BIOMETRICS_UNAVAILABLE';

/** Why a policy denied, with the evidence behind it. */
export interface PolicyReason {
  readonly code: PolicyReasonCode;
  readonly checkId?: CheckId;
  /** Signals that triggered this reason, so the decision is auditable. */
  readonly signalIds: readonly string[];
  readonly message: string;
}

/**
 * The outcome of evaluating a policy.
 *
 * The toolkit **returns this and does nothing else**. It will not block a user,
 * terminate the process, or show UI. What to do about a denial is the
 * application's decision.
 */
export interface PolicyDecision {
  readonly allowed: boolean;
  readonly reasons: readonly PolicyReason[];
  readonly risk: SecurityRisk;
  readonly report: SecurityReport;
  readonly evaluatedAt: string;
}
