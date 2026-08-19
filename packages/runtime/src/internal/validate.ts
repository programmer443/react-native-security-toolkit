import { SecurityToolkitError } from './errors';
import type {
  CheckId,
  NativeEngineInfo,
  Platform,
  SecurityCheckResult,
  SecurityConfidence,
  SecuritySignal,
  SecurityStatus,
  SignalOutcome,
  UnavailableReason,
} from '../types';

/**
 * Validation for values crossing the native boundary.
 *
 * The Codegen specification types this boundary at compile time, but a running
 * process cannot rely on that: on a compromised device the native side is
 * exactly what an attacker may control, and a hooked module can return anything
 * at all. Every payload is therefore re-checked at runtime before it is allowed
 * to reach application code (§71 of the project brief).
 */

const PLATFORMS: readonly string[] = ['android', 'ios'];

const STATUSES: readonly string[] = ['secure', 'detected', 'unknown', 'unavailable', 'error'];

const CONFIDENCES: readonly string[] = ['low', 'medium', 'high'];

const OUTCOMES: readonly string[] = ['detected', 'not-detected', 'indeterminate'];

const UNAVAILABLE_REASONS: readonly string[] = [
  'platform-not-supported',
  'permission-denied',
  'api-level-too-low',
  'not-configured',
  'disabled-by-config',
  'hardware-not-present',
  'simulator',
];

function fail(detail: string): never {
  throw new SecurityToolkitError(
    'INVALID_NATIVE_PAYLOAD',
    `The native security engine returned an unexpected payload: ${detail}`
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Reads a non-empty string property, or throws. */
export function requireString(source: Record<string, unknown>, key: string): string {
  const value = source[key];
  if (typeof value !== 'string' || value.length === 0) {
    fail(`expected "${key}" to be a non-empty string, received ${describe(value)}`);
  }
  return value;
}

/** Reads an array-of-strings property, or throws. */
export function requireStringArray(source: Record<string, unknown>, key: string): string[] {
  const value = source[key];
  if (!Array.isArray(value)) {
    fail(`expected "${key}" to be an array, received ${describe(value)}`);
  }
  return value.map((entry, index) => {
    if (typeof entry !== 'string') {
      fail(`expected "${key}[${index}]" to be a string, received ${describe(entry)}`);
    }
    return entry;
  });
}

/** Describes a value for error messages without leaking its full contents. */
function describe(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (Array.isArray(value)) {
    return `an array of length ${value.length}`;
  }
  return typeof value;
}

/** Validates and narrows a raw engine-info payload from the native module. */
export function parseEngineInfo(raw: unknown): NativeEngineInfo {
  if (!isRecord(raw)) {
    fail(`expected an object, received ${describe(raw)}`);
  }

  const platform = requireString(raw, 'platform');
  if (!PLATFORMS.includes(platform)) {
    fail(`expected "platform" to be one of ${PLATFORMS.join(' | ')}, received "${platform}"`);
  }

  return Object.freeze({
    platform: platform as Platform,
    osVersion: requireString(raw, 'osVersion'),
    engineVersion: requireString(raw, 'engineVersion'),
    supportedChecks: Object.freeze(requireStringArray(raw, 'supportedChecks')),
  });
}

function requireBoolean(source: Record<string, unknown>, key: string): boolean {
  const value = source[key];
  if (typeof value !== 'boolean') {
    fail(`expected "${key}" to be a boolean, received ${describe(value)}`);
  }
  return value;
}

function requireFiniteNumber(source: Record<string, unknown>, key: string): number {
  const value = source[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    fail(`expected "${key}" to be a finite number, received ${describe(value)}`);
  }
  return value;
}

function requireEnum<T extends string>(
  source: Record<string, unknown>,
  key: string,
  allowed: readonly string[]
): T {
  const value = requireString(source, key);
  if (!allowed.includes(value)) {
    fail(`expected "${key}" to be one of ${allowed.join(' | ')}, received "${value}"`);
  }
  return value as T;
}

/** Optional metadata bag. Anything non-object is dropped rather than trusted. */
function optionalMetadata(source: Record<string, unknown>): Readonly<Record<string, unknown>> {
  const value = source['metadata'];
  return isRecord(value) ? Object.freeze({ ...value }) : Object.freeze({});
}

function parseSignal(raw: unknown, index: number): SecuritySignal {
  if (!isRecord(raw)) {
    fail(`expected "signals[${index}]" to be an object, received ${describe(raw)}`);
  }

  const outcome = requireEnum<SignalOutcome>(raw, 'outcome', OUTCOMES);
  const detected = requireBoolean(raw, 'detected');

  // A native module that reports `detected: true` alongside an outcome of
  // `indeterminate` is either buggy or lying. Either way the payload is not
  // usable, and quietly picking one field over the other would hide it.
  if (detected !== (outcome === 'detected')) {
    fail(
      `"signals[${index}]" is internally inconsistent: outcome "${outcome}" with detected ${String(detected)}`
    );
  }

  return Object.freeze({
    id: requireString(raw, 'id'),
    outcome,
    detected,
    confidence: requireEnum<SecurityConfidence>(raw, 'confidence', CONFIDENCES),
    description: requireString(raw, 'description'),
    metadata: optionalMetadata(raw),
  });
}

/**
 * Validates and narrows a raw check-result payload from the native module.
 *
 * @param raw the value returned across the bridge
 * @param platform the platform the result was produced on
 * @param expectedId the check that was requested, so a native module cannot
 *   answer a different question than the one asked
 */
export function parseCheckResult(
  raw: unknown,
  platform: Platform,
  expectedId: CheckId
): SecurityCheckResult {
  if (!isRecord(raw)) {
    fail(`expected an object, received ${describe(raw)}`);
  }

  const id = requireString(raw, 'id');
  if (id !== expectedId) {
    fail(`expected a result for "${expectedId}", received one for "${id}"`);
  }

  const status = requireEnum<SecurityStatus>(raw, 'status', STATUSES);
  const detected = requireBoolean(raw, 'detected');

  if (detected !== (status === 'detected')) {
    fail(`result is internally inconsistent: status "${status}" with detected ${String(detected)}`);
  }

  const rawSignals = raw['signals'];
  if (!Array.isArray(rawSignals)) {
    fail(`expected "signals" to be an array, received ${describe(rawSignals)}`);
  }
  const signals = rawSignals.map(parseSignal);

  // `detected` must be earned by at least one signal. Without this, a hooked
  // native module could assert a verdict with no evidence behind it — or, more
  // dangerously, assert `secure` while signals say otherwise.
  const anySignalDetected = signals.some((signal) => signal.detected);
  if (status === 'detected' && !anySignalDetected) {
    fail('status is "detected" but no signal reported a detection');
  }
  if (status === 'secure' && anySignalDetected) {
    fail('status is "secure" but at least one signal reported a detection');
  }

  const checkedAtEpochMs = requireFiniteNumber(raw, 'checkedAtEpochMs');

  const unavailableReason =
    raw['unavailableReason'] === undefined || raw['unavailableReason'] === null
      ? undefined
      : requireEnum<UnavailableReason>(raw, 'unavailableReason', UNAVAILABLE_REASONS);

  const errorMessage =
    raw['errorMessage'] === undefined || raw['errorMessage'] === null
      ? undefined
      : requireString(raw, 'errorMessage');

  return Object.freeze({
    id: expectedId,
    status,
    detected,
    confidence: requireEnum<SecurityConfidence>(raw, 'confidence', CONFIDENCES),
    platform,
    signals: Object.freeze(signals),
    ...(unavailableReason === undefined ? {} : { unavailableReason }),
    ...(errorMessage === undefined ? {} : { errorMessage }),
    metadata: optionalMetadata(raw),
    durationMs: requireFiniteNumber(raw, 'durationMs'),
    // The native side reports epoch milliseconds; the ISO representation is
    // produced in one place, here, so both platforms cannot drift in format.
    checkedAt: new Date(checkedAtEpochMs).toISOString(),
  });
}
