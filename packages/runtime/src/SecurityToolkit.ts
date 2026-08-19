import {
  getConfiguration as readConfiguration,
  resetConfiguration,
  setConfiguration,
} from './internal/config';
import { currentPlatform, getNativeModule, isNativeModuleAvailable } from './internal/nativeModule';
import { withTimeout } from './internal/timeout';
import { parseEngineInfo } from './internal/validate';
import { evaluatePolicy } from './policy/policyEngine';
import { checkAll } from './runtime/checkAll';
import type {
  NativeEngineInfo,
  Platform,
  PolicyDecision,
  ResolvedSecurityToolkitOptions,
  SecurityPolicy,
  SecurityReport,
  SecurityToolkitOptions,
} from './types';

/**
 * Entry point to the React Native Security Toolkit.
 *
 * The toolkit reports; it never reacts. No method here blocks a user, terminates
 * the process, shows UI, or performs a network request. What to do about a
 * result is the application's decision (§73 of the project brief).
 *
 * @remarks
 * Runtime security checks are defence-in-depth signals. A sophisticated
 * attacker with control of the device may defeat individual checks, or several
 * at once. Treat results as evidence to weigh, never as a guarantee that a
 * device or application is uncompromised.
 */
export const SecurityToolkit = {
  /**
   * Applies toolkit-wide configuration.
   *
   * @throws {@link SecurityToolkitError} with code `INVALID_CONFIGURATION` when
   * an option is malformed. Configuration errors are programmer errors and are
   * surfaced loudly rather than silently defaulted.
   */
  configure(options: SecurityToolkitOptions): void {
    setConfiguration(options);
  },

  /** Returns the configuration currently in effect, with defaults applied. */
  getConfiguration(): ResolvedSecurityToolkitOptions {
    return readConfiguration();
  },

  /** Restores the default configuration. */
  resetConfiguration(): void {
    resetConfiguration();
  },

  /**
   * Whether the native security engine is linked and reachable.
   *
   * Never throws. Call this before other APIs when the host application can
   * meaningfully degrade rather than fail.
   */
  isAvailable(): boolean {
    return isNativeModuleAvailable() && currentPlatform() !== null;
  },

  /** The platform the toolkit is running on, or `null` where it is unsupported. */
  getPlatform(): Platform | null {
    return currentPlatform();
  },

  /**
   * Returns identifying information about the native engine.
   *
   * Useful as an installation smoke test: a successful call proves the
   * TypeScript API, the Codegen-generated bridge and the native engine are all
   * wired together correctly.
   *
   * @throws {@link SecurityToolkitError} with code `NATIVE_MODULE_UNAVAILABLE`,
   * `NATIVE_TIMEOUT`, or `INVALID_NATIVE_PAYLOAD`.
   */
  async getEngineInfo(): Promise<NativeEngineInfo> {
    const native = getNativeModule();
    const { nativeTimeoutMs } = readConfiguration();
    const raw = await withTimeout(
      native.getEngineInfo(),
      nativeTimeoutMs,
      'SecurityToolkit.getEngineInfo()'
    );
    return parseEngineInfo(raw);
  },

  /**
   * Runs every check this platform implements and scores the result.
   *
   * Checks the platform does not implement are **absent** from
   * {@link SecurityReport.checks}, not present as errors. All checks run in a
   * single bridge crossing.
   *
   * @throws {@link SecurityToolkitError} only when the native module is not
   * linked. Device conditions resolve as results, never as rejections.
   */
  async checkAll(): Promise<SecurityReport> {
    return checkAll();
  },

  /**
   * Runs every check and evaluates `policy` against the result.
   *
   * @remarks
   * This **returns a decision and does nothing else**. It will not block a user,
   * terminate the process, show UI, or make a network request. What to do about
   * a denial is the application's decision — see
   * `docs/runtime/security-policy.md` for why an in-process kill switch is the
   * wrong tool.
   *
   * @example
   * ```ts
   * const decision = await SecurityToolkit.evaluate({
   *   blockOnRoot: true,
   *   minimumConfidence: 'high',
   * });
   *
   * if (!decision.allowed) {
   *   // decision.reasons carries the evidence behind each denial.
   * }
   * ```
   */
  async evaluate(policy: SecurityPolicy): Promise<PolicyDecision> {
    return evaluatePolicy(await checkAll(), policy);
  },
} as const;
