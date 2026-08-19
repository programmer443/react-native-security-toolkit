import { SecurityToolkitError } from './errors';
import type {
  CheckId,
  IntegrityOptions,
  ResolvedSecurityToolkitOptions,
  SecurityToolkitOptions,
} from '../types';

const VALID_CHECK_IDS: readonly CheckId[] = [
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

const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 60_000;

export const DEFAULT_OPTIONS: ResolvedSecurityToolkitOptions = Object.freeze({
  developmentMode: false,
  nativeTimeoutMs: 5_000,
  disabledChecks: Object.freeze([]) as readonly CheckId[],
  integrity: Object.freeze({}) as IntegrityOptions,
});

let current: ResolvedSecurityToolkitOptions = DEFAULT_OPTIONS;

function invalid(detail: string): never {
  throw new SecurityToolkitError('INVALID_CONFIGURATION', `Invalid configuration: ${detail}`);
}

/**
 * Validates and resolves caller-supplied options.
 *
 * Configuration mistakes are thrown rather than silently corrected: a typo in
 * `disabledChecks` that quietly disabled nothing — or quietly disabled the
 * wrong check — is precisely the kind of failure a security package must not
 * absorb.
 */
export function resolveOptions(options: SecurityToolkitOptions): ResolvedSecurityToolkitOptions {
  if (typeof options !== 'object' || options === null) {
    invalid('expected an options object');
  }

  const { developmentMode, nativeTimeoutMs, disabledChecks, integrity } = options;

  if (developmentMode !== undefined && typeof developmentMode !== 'boolean') {
    invalid('"developmentMode" must be a boolean');
  }

  if (nativeTimeoutMs !== undefined) {
    if (typeof nativeTimeoutMs !== 'number' || !Number.isFinite(nativeTimeoutMs)) {
      invalid('"nativeTimeoutMs" must be a finite number');
    }
    if (nativeTimeoutMs < MIN_TIMEOUT_MS || nativeTimeoutMs > MAX_TIMEOUT_MS) {
      invalid(`"nativeTimeoutMs" must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`);
    }
  }

  if (disabledChecks !== undefined) {
    if (!Array.isArray(disabledChecks)) {
      invalid('"disabledChecks" must be an array');
    }
    for (const id of disabledChecks) {
      if (!VALID_CHECK_IDS.includes(id as CheckId)) {
        invalid(
          `"disabledChecks" contains unknown check "${String(id)}". ` +
            `Valid checks: ${VALID_CHECK_IDS.join(', ')}`
        );
      }
    }
  }

  return Object.freeze({
    developmentMode: developmentMode ?? DEFAULT_OPTIONS.developmentMode,
    nativeTimeoutMs: nativeTimeoutMs ?? DEFAULT_OPTIONS.nativeTimeoutMs,
    disabledChecks: Object.freeze([...(disabledChecks ?? DEFAULT_OPTIONS.disabledChecks)]),
    integrity: resolveIntegrity(integrity),
  });
}

/**
 * Validates integrity configuration.
 *
 * Mistakes here are worth being loud about: a mistyped signing fingerprint would
 * make every launch look like a tampered build, and an empty pin array would
 * silently disable the strongest integrity signal there is.
 */
function resolveIntegrity(integrity: IntegrityOptions | undefined): IntegrityOptions {
  if (integrity === undefined) {
    return DEFAULT_OPTIONS.integrity;
  }

  if (typeof integrity !== 'object' || integrity === null) {
    invalid('"integrity" must be an object');
  }

  const {
    signingCertificateSha256,
    expectedInstallers,
    expectedPackageName,
    expectedBundleIdentifier,
  } = integrity;

  if (signingCertificateSha256 !== undefined) {
    if (!Array.isArray(signingCertificateSha256) || signingCertificateSha256.length === 0) {
      invalid('"integrity.signingCertificateSha256" must be a non-empty array');
    }
    for (const fingerprint of signingCertificateSha256) {
      if (typeof fingerprint !== 'string') {
        invalid('"integrity.signingCertificateSha256" must contain only strings');
      }
      // 32 bytes, however the caller chose to punctuate them.
      if (fingerprint.replace(/[^0-9a-fA-F]/g, '').length !== 64) {
        invalid(
          `"integrity.signingCertificateSha256" contains a value that is not a SHA-256 ` +
            `fingerprint: "${fingerprint}"`
        );
      }
    }
  }

  if (expectedInstallers !== undefined) {
    if (!Array.isArray(expectedInstallers) || expectedInstallers.length === 0) {
      invalid('"integrity.expectedInstallers" must be a non-empty array');
    }
    for (const installer of expectedInstallers) {
      if (typeof installer !== 'string' || installer.length === 0) {
        invalid('"integrity.expectedInstallers" must contain only non-empty strings');
      }
    }
  }

  if (expectedPackageName !== undefined) {
    if (typeof expectedPackageName !== 'string' || expectedPackageName.length === 0) {
      invalid('"integrity.expectedPackageName" must be a non-empty string');
    }
  }

  if (expectedBundleIdentifier !== undefined) {
    if (typeof expectedBundleIdentifier !== 'string' || expectedBundleIdentifier.length === 0) {
      invalid('"integrity.expectedBundleIdentifier" must be a non-empty string');
    }
  }

  return Object.freeze({
    ...(signingCertificateSha256 === undefined
      ? {}
      : { signingCertificateSha256: Object.freeze([...signingCertificateSha256]) }),
    ...(expectedInstallers === undefined
      ? {}
      : { expectedInstallers: Object.freeze([...expectedInstallers]) }),
    ...(expectedPackageName === undefined ? {} : { expectedPackageName }),
    ...(expectedBundleIdentifier === undefined ? {} : { expectedBundleIdentifier }),
  });
}

/** Applies configuration for subsequent calls. */
export function setConfiguration(options: SecurityToolkitOptions): void {
  current = resolveOptions(options);
}

/** Returns the configuration currently in effect. */
export function getConfiguration(): ResolvedSecurityToolkitOptions {
  return current;
}

/** Restores defaults. Exposed for tests and for host apps that reset between sessions. */
export function resetConfiguration(): void {
  current = DEFAULT_OPTIONS;
}
