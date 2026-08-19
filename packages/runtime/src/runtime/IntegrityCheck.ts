import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

/**
 * Application integrity.
 *
 * Reports whether the running application matches what you published: its
 * signing certificate, the package that installed it, its package name, and
 * where the APK is running from.
 *
 * @remarks
 * Three of the four signals need configuration through
 * {@link SecurityToolkit.configure} — there is no way to know whether a signing
 * certificate is the right one without being told which one is right. An
 * unconfigured signal reports `indeterminate`, never a passing result, so a
 * check that was never really performed can never look like one that passed.
 *
 * Genuine integrity assurance on Android comes from **Play Integrity**, verified
 * on your server. These signals detect sideloading, re-signing and repackaging
 * cheaply and locally; they do not replace attestation, and an attacker who
 * controls the device can defeat them.
 *
 * @example
 * ```ts
 * SecurityToolkit.configure({
 *   integrity: {
 *     signingCertificateSha256: ['A1:B2:…'],
 *     expectedInstallers: ['com.android.vending'],
 *     expectedPackageName: 'com.example.app',
 *   },
 * });
 *
 * const integrity = await IntegrityCheck.getStatus();
 * ```
 *
 * @see docs/runtime/integrity.md
 */
export const IntegrityCheck: {
  getStatus(): Promise<SecurityCheckResult>;
} = {
  getStatus: createCheck('integrity'),
};
