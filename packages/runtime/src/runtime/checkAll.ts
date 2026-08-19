import { getConfiguration } from '../internal/config';
import { currentPlatform, getNativeModule } from '../internal/nativeModule';
import { withTimeout } from '../internal/timeout';
import { parseCheckResult, parseEngineInfo } from '../internal/validate';
import { evaluateRisk } from '../risk/riskEngine';
import type { CheckId, SecurityCheckResult, SecurityReport } from '../types';

/**
 * Runs every check this platform implements.
 *
 * Two properties matter here beyond "call all the checks":
 *
 * **Platform asymmetry is expressed by absence.** The engine is asked which
 * checks it implements, and only those appear in the report. On Android there is
 * no `jailbreak` key at all — not a `jailbreak` entry saying "error", and not one
 * saying "unavailable". A check that does not exist on a platform is not a
 * failure of that platform, and a report full of phantom failures is one nobody
 * reads carefully.
 *
 * **One bridge crossing.** All checks run in a single `runChecks` call rather
 * than one call each, so the cost is one hop plus the native work.
 *
 * **The timeout scales with the work.** `nativeTimeoutMs` is a budget for *one*
 * check. Applying it to a batch of nine would mean they share what one was
 * allotted, which is exactly how a cold start ends up reported as a timeout
 * rather than as a result — measured cold-start costs on Android reach ~1.7s for
 * root alone.
 */

/**
 * Ceiling on the scaled batch budget, matching the maximum a caller may set for
 * a single check. However many checks a platform grows, `checkAll()` still
 * answers within a minute or reports an error.
 */
const MAX_BATCH_TIMEOUT_MS = 60_000;

/**
 * Cached because the engine's check list is fixed at build time. Cleared by
 * {@link __resetCheckAllCacheForTesting}.
 */
let cachedSupportedChecks: readonly CheckId[] | undefined;
let cachedEngineVersion: string | undefined;

const ALL_CHECK_IDS: readonly CheckId[] = [
  'root',
  'jailbreak',
  'debugger',
  'emulator',
  'simulator',
  'hooks',
  'integrity',
  'secureHardware',
  'biometrics',
  'network',
  'screen',
];

export async function checkAll(): Promise<SecurityReport> {
  const startedAt = Date.now();
  const native = getNativeModule();
  const platform = currentPlatform() ?? 'android';
  const { disabledChecks, nativeTimeoutMs, developmentMode, integrity } = getConfiguration();

  if (cachedSupportedChecks === undefined || cachedEngineVersion === undefined) {
    const info = parseEngineInfo(
      await withTimeout(native.getEngineInfo(), nativeTimeoutMs, 'SecurityToolkit.checkAll()')
    );
    // An engine reporting a check this version of the JavaScript does not know
    // about is a version mismatch, not something to guess at.
    cachedSupportedChecks = Object.freeze(
      info.supportedChecks.filter((id): id is CheckId => ALL_CHECK_IDS.includes(id as CheckId))
    );
    cachedEngineVersion = info.engineVersion;
  }

  const requested = cachedSupportedChecks.filter((id) => !disabledChecks.includes(id));
  const checks: Partial<Record<CheckId, SecurityCheckResult>> = {};

  // Disabled checks are still reported — they exist on this platform, they were
  // just switched off. Silently omitting them would be indistinguishable from
  // the platform not having them.
  for (const id of cachedSupportedChecks) {
    if (disabledChecks.includes(id)) {
      checks[id] = disabledResult(id, platform);
    }
  }

  if (requested.length > 0) {
    const options = requested.includes('integrity') ? integrity : {};
    const batchTimeoutMs = Math.min(nativeTimeoutMs * requested.length, MAX_BATCH_TIMEOUT_MS);
    const raw = await withTimeout(
      native.runChecks([...requested], options),
      batchTimeoutMs,
      'SecurityToolkit.checkAll()'
    );

    for (const [index, id] of requested.entries()) {
      checks[id] = parseResultAt(raw, index, platform, id);
    }
  }

  const risk = evaluateRisk(checks, { developmentMode });

  return Object.freeze({
    compromised: risk.level === 'high' || risk.level === 'critical',
    risk,
    platform,
    checks: Object.freeze(checks),
    engineVersion: cachedEngineVersion,
    durationMs: Date.now() - startedAt,
    checkedAt: new Date(startedAt).toISOString(),
  });
}

/**
 * Reads one result out of the batch payload.
 *
 * A malformed entry degrades that one check to `error` rather than failing the
 * whole report: losing ten good results because the eleventh was malformed would
 * be a poor trade.
 */
function parseResultAt(
  raw: unknown,
  index: number,
  platform: 'android' | 'ios',
  id: CheckId
): SecurityCheckResult {
  try {
    const results = (raw as { results?: unknown }).results;
    if (!Array.isArray(results)) {
      throw new Error('The native engine returned no results array');
    }
    return parseCheckResult(results[index], platform, id);
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

/**
 * Clears the cached engine capabilities.
 *
 * @internal Not part of the public API.
 */
export function __resetCheckAllCacheForTesting(): void {
  cachedSupportedChecks = undefined;
  cachedEngineVersion = undefined;
}
