import { TurboModuleRegistry, type TurboModule } from 'react-native';

/**
 * Codegen specification for the native security engine.
 *
 * Deliberately primitive, and deliberately generic. Codegen supports only a
 * narrow type vocabulary, and a per-check method would force every platform to
 * implement every other platform's checks just to satisfy the generated
 * protocol — iOS would need a `getRootStatus` that answers "not applicable".
 * A single `runCheck` plus a platform-specific `supportedChecks` list expresses
 * platform asymmetry honestly: a check that does not exist here is absent, not
 * failed.
 *
 * Payloads crossing this boundary are re-validated at runtime by
 * `src/internal/validate.ts`. The generated types are a compile-time
 * convenience; on a compromised device the native side is what an attacker may
 * control.
 */
export interface Spec extends TurboModule {
  /** Identifying information about the native engine, including its check list. */
  getEngineInfo(): Promise<{
    platform: string;
    osVersion: string;
    engineVersion: string;
    supportedChecks: Array<string>;
  }>;

  /**
   * Runs one check. Unknown or unsupported ids resolve as `unavailable`, never reject.
   *
   * `options` carries per-call configuration, such as the signing certificate
   * fingerprints the integrity check should expect. Passing it per call rather
   * than storing it natively keeps the native engine stateless — there is no
   * `configure()` whose ordering relative to a check could matter.
   */
  runCheck(checkId: string, options: Object): Promise<Object>;

  /** Runs several checks in one bridge crossing. */
  runChecks(checkIds: Array<string>, options: Object): Promise<Object>;

  /**
   * Applies or removes screen capture protection.
   *
   * The only mutating method on this interface. Resolves to whether the change
   * reached a live window — `false` means the intent was recorded and will apply
   * when a window appears, not that the request failed.
   */
  setScreenProtection(enabled: boolean): Promise<boolean>;
}

/**
 * Resolved lazily and **without** `getEnforcing`.
 *
 * `getEnforcing` throws at import time when the native module is missing, which
 * would crash a host application merely for importing this package. Returning
 * `null` lets the JavaScript layer surface a controlled, actionable error
 * instead (§51 of the project brief).
 */
export default TurboModuleRegistry.get<Spec>('SecurityToolkit');
