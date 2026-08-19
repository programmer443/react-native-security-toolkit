import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

/**
 * Android root detection.
 *
 * Combines ten independent indicators — su binaries, root management
 * applications, build and boot-state properties, mount anomalies, writable
 * system paths, SELinux state, and Magisk/Zygisk artefacts — into a single
 * result carrying every signal that produced it.
 *
 * @remarks
 * Root detection is a defence-in-depth signal, not a guarantee. Every indicator
 * here can be defeated by an attacker who controls the device, and several can
 * be defeated together. Treat `detected` as grounds for reducing what the app
 * will do, not as proof, and treat `unknown` as inconclusive rather than safe.
 *
 * On iOS this reports `unavailable` with `platform-not-supported`; use
 * `JailbreakDetection` there.
 *
 * @example
 * ```ts
 * const root = await RootDetection.getStatus();
 *
 * if (root.status === 'detected' && root.confidence === 'high') {
 *   // The application decides what this means. The toolkit does not.
 * }
 * ```
 *
 * @see docs/runtime/root-detection.md
 */
export const RootDetection: {
  getStatus(): Promise<SecurityCheckResult>;
} = {
  getStatus: createCheck('root'),
};
