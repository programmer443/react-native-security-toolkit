import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

const getStatus = createCheck('emulator');

/**
 * Emulator detection (Android).
 *
 * Reports whether the application appears to be running on an emulator or a
 * virtualised Android image, based on build identity, emulator-only device
 * nodes and properties, and hardware profile.
 *
 * @remarks
 * Running under emulation is **not** a compromise. Continuous integration runs
 * on emulators, QA runs on device farms, and Google Play Games runs Android apps
 * on desktop hardware. Treat this as one input to a risk decision, not as
 * grounds to block a user.
 *
 * On iOS this reports `unavailable`; use `SimulatorDetection` there.
 *
 * @see docs/runtime/emulator-detection.md
 */
export const EmulatorDetection: {
  getStatus(): Promise<SecurityCheckResult>;
  isEmulator(): Promise<boolean>;
} = {
  getStatus,

  /**
   * Convenience wrapper returning a single boolean.
   *
   * Returns `true` only when the check reached a `detected` verdict. Every other
   * outcome — including `unknown` — returns `false`, because a boolean has
   * nowhere to put "inconclusive". Prefer {@link getStatus} when the difference
   * matters.
   */
  async isEmulator(): Promise<boolean> {
    return (await getStatus()).status === 'detected';
  },
};
