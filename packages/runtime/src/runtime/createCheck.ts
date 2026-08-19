import { getConfiguration } from '../internal/config';
import { currentPlatform, getNativeModule } from '../internal/nativeModule';
import { withTimeout } from '../internal/timeout';
import { parseCheckResult } from '../internal/validate';
import type { CheckId, SecurityCheckResult } from '../types';

/**
 * Builds the `getStatus()` function for one check.
 *
 * All the shared behaviour a check needs lives here so that adding a detector is
 * a native-side change, not a copy of twelve lines of JavaScript per check.
 *
 * Failure handling is the interesting part. Two conditions resolve to a *result*
 * rather than rejecting, because neither is a programmer error and neither
 * should oblige an app to wrap every check in try/catch:
 *
 * - the check is switched off in configuration → `disabled-by-config`
 * - the native call fails or times out → `error`
 *
 * Platform support is deliberately **not** decided here. Each platform's engine
 * answers for itself and returns `unavailable` with `platform-not-supported` for
 * a check it does not implement. Encoding "root is Android-only" in JavaScript
 * would duplicate that knowledge and let the two drift apart the moment a
 * platform gains a check.
 *
 * A missing native module still throws: that is a build problem the developer
 * must fix, not a device condition to be reported.
 */
export function createCheck(id: CheckId): () => Promise<SecurityCheckResult> {
  return async function getStatus(): Promise<SecurityCheckResult> {
    const { disabledChecks, nativeTimeoutMs, integrity } = getConfiguration();

    // Throws only when the native module is absent — a build problem, not a
    // device condition.
    const native = getNativeModule();
    const platform = currentPlatform() ?? 'android';

    if (disabledChecks.includes(id)) {
      return disabledResult(id, platform);
    }

    try {
      // Only the options a check actually needs are sent, so a check cannot
      // read configuration meant for another one.
      const options = id === 'integrity' ? integrity : {};
      const raw = await withTimeout(
        native.runCheck(id, options),
        nativeTimeoutMs,
        `SecurityToolkit check "${id}"`
      );
      return parseCheckResult(raw, platform, id);
    } catch (error: unknown) {
      return {
        id,
        status: 'error',
        detected: false,
        confidence: 'low',
        platform,
        signals: [],
        errorMessage: error instanceof Error ? error.message : String(error),
        metadata: {},
        durationMs: 0,
        checkedAt: new Date().toISOString(),
      };
    }
  };
}

function disabledResult(id: CheckId, platform: 'android' | 'ios'): SecurityCheckResult {
  return {
    id,
    status: 'unavailable',
    detected: false,
    confidence: 'low',
    platform,
    signals: [],
    unavailableReason: 'disabled-by-config',
    metadata: {},
    durationMs: 0,
    checkedAt: new Date().toISOString(),
  };
}
