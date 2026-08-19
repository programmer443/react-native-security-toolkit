import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

/**
 * Biometric authentication capability.
 *
 * Reports whether strong (Class 3) biometric authentication is usable, whether
 * anything is enrolled, and whether a device credential is set at all.
 *
 * @remarks
 * **No biometric data is read, stored, transmitted or exposed** by this check,
 * and none is available to it — the platform reports a status code and nothing
 * more. Nothing here can identify a user.
 *
 * Like {@link SecureHardware}, this is a capability report: `detected` means a
 * weakness indicator fired, not that an attack was found. And an unenrolled
 * device is not an insecure device — plenty of people deliberately use a PIN and
 * no biometric. These signals exist so an application can decide whether
 * biometric authentication is a viable gate, not so it can nag.
 *
 * @see docs/runtime/biometrics.md
 */
export const BiometricSecurity: {
  getStatus(): Promise<SecurityCheckResult>;
} = {
  getStatus: createCheck('biometrics'),
};
