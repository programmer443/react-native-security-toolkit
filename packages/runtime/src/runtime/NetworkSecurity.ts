import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

/**
 * Network posture.
 *
 * Reports whether this application may send cleartext HTTP, whether a proxy or
 * VPN is in use, and whether user-added certificate authorities are installed.
 *
 * @remarks
 * **A mobile application cannot reliably detect an interception attack**, and
 * nothing here should be read as if it could. A competent attacker on the
 * network path leaves no trace visible from inside the process. These signals
 * describe configuration and device posture — useful inputs to a risk decision,
 * not evidence of an attack.
 *
 * Proxy and VPN signals in particular are informational: both are entirely
 * mainstream, and blocking on them blocks a great many legitimate users.
 *
 * @see docs/runtime/network-security.md
 */
export const NetworkSecurity: {
  getStatus(): Promise<SecurityCheckResult>;
} = {
  getStatus: createCheck('network'),
};
