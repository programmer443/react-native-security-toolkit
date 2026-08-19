import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

/**
 * iOS jailbreak detection.
 *
 * Combines seven independent indicators — classic and rootless filesystem
 * artefacts, a sandbox escape probe, injected libraries, the dyld insertion
 * environment variable, package-manager URL schemes, and symbolic-link anomalies
 * — into a single result carrying every signal that produced it.
 *
 * @remarks
 * Jailbreak detection is a defence-in-depth signal, not a guarantee. Every
 * indicator here can be defeated by an attacker who controls the device, and
 * several can be defeated together. Treat `detected` as grounds for reducing what
 * the app will do, and `unknown` as inconclusive rather than safe.
 *
 * Path-based signals are versioned rather than hardcoded, because this is the
 * data that ages fastest: modern rootless jailbreaks relocate their filesystem,
 * so lists written for the `/Applications/Cydia.app` era under-detect badly while
 * appearing thorough.
 *
 * On Android this reports `unavailable` with `platform-not-supported`; use
 * `RootDetection` there.
 *
 * @see docs/runtime/jailbreak-detection.md
 */
export const JailbreakDetection: {
  getStatus(): Promise<SecurityCheckResult>;
} = {
  getStatus: createCheck('jailbreak'),
};
