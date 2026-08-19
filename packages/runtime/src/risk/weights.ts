import type { CheckId } from '../types';

/**
 * Versioned risk weights.
 *
 * Every number here is a judgement call, so they live in one table rather than
 * scattered through scoring code: a weight change is then a reviewable diff
 * rather than an archaeology exercise, and the golden-vector tests in
 * `src/__tests__/riskEngine.test.ts` fail loudly when one moves.
 *
 * Weights are **base points before the confidence multiplier**. A signal's final
 * contribution is `points × confidenceMultiplier`, so a weak observation of a
 * severe condition scores lower than a strong one — confidence is a property of
 * the evidence, not of the consequence.
 *
 * @see docs/runtime/risk-scoring.md
 */

/** Bumped on any change to weights or scoring rules. Reported in every result. */
export const RISK_METHODOLOGY_VERSION = 'rnsec-risk-1';

/** Confidence multipliers applied to a signal's base points. */
export const CONFIDENCE_MULTIPLIER = Object.freeze({
  low: 0.4,
  medium: 0.7,
  high: 1.0,
});

/**
 * Base points per signal.
 *
 * The rough scale: **35–40** for something that alone justifies distrusting the
 * device, **20–30** for a strong indicator, **10–15** for a real but ambiguous
 * one, and **2–8** for posture that is worth recording and little more.
 */
export const SIGNAL_WEIGHTS: Readonly<Record<string, number>> = Object.freeze({
  // ── Android root ─────────────────────────────────────────────────────────
  // Verified Boot and a writable system partition are the two that are hard to
  // explain away innocently.
  'RNSEC-ANDROID-ROOT-005': 35,
  'RNSEC-ANDROID-ROOT-008': 35,
  'RNSEC-ANDROID-ROOT-001': 30,
  'RNSEC-ANDROID-ZYGISK-001': 30,
  'RNSEC-ANDROID-MAGISK-001': 25,
  'RNSEC-ANDROID-ROOT-002': 20,
  'RNSEC-ANDROID-ROOT-007': 20,
  'RNSEC-ANDROID-ROOT-009': 20,
  'RNSEC-ANDROID-ROOT-003': 15,
  // Custom-ROM users are not attackers; this stays deliberately cheap.
  'RNSEC-ANDROID-ROOT-004': 8,

  // ── iOS jailbreak ────────────────────────────────────────────────────────
  'RNSEC-IOS-JAILBREAK-003': 40,
  'RNSEC-IOS-JAILBREAK-004': 35,
  'RNSEC-IOS-JAILBREAK-005': 35,
  'RNSEC-IOS-JAILBREAK-002': 25,
  'RNSEC-IOS-JAILBREAK-006': 20,
  'RNSEC-IOS-JAILBREAK-007': 20,
  'RNSEC-IOS-JAILBREAK-001': 15,

  // ── Hooking and instrumentation ──────────────────────────────────────────
  'RNSEC-RUNTIME-HOOK-003': 30,
  'RNSEC-RUNTIME-HOOK-004': 30,
  'RNSEC-RUNTIME-HOOK-001': 25,
  'RNSEC-RUNTIME-HOOK-002': 25,
  // Legitimate SDKs swizzle, so this must not be expensive on its own.
  'RNSEC-RUNTIME-HOOK-005': 15,

  // ── Debugger ─────────────────────────────────────────────────────────────
  'RNSEC-ANDROID-DEBUGGER-001': 15,
  'RNSEC-ANDROID-DEBUGGER-002': 15,
  'RNSEC-ANDROID-DEBUGGER-003': 10,
  'RNSEC-ANDROID-DEBUGGER-005': 8,
  // Developer options are on for a great many ordinary users.
  'RNSEC-ANDROID-DEBUGGER-004': 3,
  'RNSEC-IOS-DEBUGGER-001': 15,
  'RNSEC-IOS-DEBUGGER-002': 8,

  // ── Emulator and simulator ───────────────────────────────────────────────
  // Emulation is not compromise. CI, QA farms and Play Games on PC all run here.
  'RNSEC-ANDROID-EMULATOR-001': 5,
  'RNSEC-ANDROID-EMULATOR-002': 5,
  'RNSEC-ANDROID-EMULATOR-003': 2,
  'RNSEC-IOS-SIMULATOR-001': 3,

  // ── Integrity ────────────────────────────────────────────────────────────
  // A wrong signing certificate or bundle identity is about as serious as a
  // local signal gets.
  'RNSEC-RUNTIME-INTEGRITY-001': 40,
  'RNSEC-RUNTIME-INTEGRITY-003': 40,
  'RNSEC-RUNTIME-INTEGRITY-002': 10,
  'RNSEC-RUNTIME-INTEGRITY-004': 10,
  'RNSEC-IOS-INTEGRITY-001': 40,
  'RNSEC-IOS-INTEGRITY-003': 12,
  'RNSEC-IOS-INTEGRITY-002': 8,

  // ── Secure hardware ──────────────────────────────────────────────────────
  'RNSEC-RUNTIME-HARDWARE-001': 12,
  'RNSEC-IOS-HARDWARE-001': 12,
  'RNSEC-RUNTIME-HARDWARE-003': 5,
  'RNSEC-IOS-HARDWARE-002': 5,
  // Most Android devices have no StrongBox. Its absence is unremarkable.
  'RNSEC-RUNTIME-HARDWARE-002': 2,

  // ── Biometrics ───────────────────────────────────────────────────────────
  // No lock screen is a real weakness. Not enrolling a fingerprint is a choice.
  'RNSEC-RUNTIME-BIOMETRIC-003': 15,
  'RNSEC-IOS-BIOMETRIC-003': 15,
  'RNSEC-RUNTIME-BIOMETRIC-001': 5,
  'RNSEC-IOS-BIOMETRIC-001': 5,
  'RNSEC-RUNTIME-BIOMETRIC-002': 3,
  'RNSEC-IOS-BIOMETRIC-002': 3,

  // ── Network ──────────────────────────────────────────────────────────────
  'RNSEC-ANDROID-NETWORK-001': 15,
  'RNSEC-IOS-NETWORK-001': 15,
  'RNSEC-ANDROID-NETWORK-004': 8,
  // Proxies and VPNs are mainstream. Scoring them meaningfully would penalise
  // ordinary users for ordinary behaviour.
  'RNSEC-ANDROID-NETWORK-002': 2,
  'RNSEC-ANDROID-NETWORK-003': 2,
  'RNSEC-IOS-NETWORK-002': 2,
  'RNSEC-IOS-NETWORK-003': 2,

  // ── Screen ───────────────────────────────────────────────────────────────
  'RNSEC-IOS-SCREEN-001': 10,
  'RNSEC-ANDROID-SCREEN-001': 5,
});

/**
 * Points for a detected signal with no entry above.
 *
 * A new detector should be given a weight deliberately; until it is, it scores
 * modestly rather than silently scoring zero. Zero would let a new signal fire
 * with no effect on the score at all, which is the failure mode most likely to
 * go unnoticed.
 */
export const UNWEIGHTED_SIGNAL_POINTS = 10;

/**
 * Credits for checks that completed cleanly.
 *
 * Only awarded for `secure` — never for `unknown`. A check that could not reach
 * a verdict has demonstrated nothing and earns nothing.
 */
export const MITIGATION_CREDITS: Readonly<Partial<Record<CheckId, number>>> = Object.freeze({
  integrity: 10,
  secureHardware: 8,
  biometrics: 5,
  screen: 3,
});

/**
 * Points added for each check that could not reach a verdict.
 *
 * Uncertainty is not the same as compromise, but it is not the same as safety
 * either. A small, capped penalty reflects reduced assurance without letting a
 * device with unreadable probes drift into `critical` on ignorance alone.
 */
export const UNKNOWN_CHECK_PENALTY = 4;

/** Ceiling on the total uncertainty penalty. */
export const MAX_UNKNOWN_PENALTY = 12;

/**
 * Checks whose signals are ignored while `developmentMode` is enabled.
 *
 * Debuggers, emulators and simulators are where software is built. Scoring them
 * in development produces a permanently alarming number that developers learn to
 * ignore — which costs more than it buys.
 */
export const DEVELOPMENT_MODE_IGNORED_CHECKS: readonly CheckId[] = Object.freeze([
  'debugger',
  'emulator',
  'simulator',
]);

/** Score boundaries, inclusive lower bounds. */
export const RISK_LEVEL_THRESHOLDS = Object.freeze([
  { level: 'critical', minimum: 80 },
  { level: 'high', minimum: 60 },
  { level: 'medium', minimum: 40 },
  { level: 'low', minimum: 20 },
  { level: 'minimal', minimum: 0 },
] as const);
