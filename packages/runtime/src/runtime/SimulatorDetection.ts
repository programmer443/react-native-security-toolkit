import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

const getStatus = createCheck('simulator');

/**
 * Simulator detection (iOS).
 *
 * Reports whether the application is running on the iOS Simulator rather than a
 * physical device.
 *
 * @remarks
 * Running on a simulator is **not** a compromise — it is where nearly all
 * development and much automated testing happens. This exists so an application
 * can tell a simulated environment from a physical one, and so other checks can
 * decline to answer questions that are malformed there: jailbreak detection, for
 * instance, reports `unavailable` with reason `simulator`.
 *
 * Unlike Android emulator detection, this needs no signature list and has no
 * meaningful false-negative surface — the compile-time environment flag is exact.
 *
 * On Android this reports `unavailable`; use `EmulatorDetection` there.
 *
 * @see docs/runtime/simulator-detection.md
 */
export const SimulatorDetection: {
  getStatus(): Promise<SecurityCheckResult>;
  isSimulator(): Promise<boolean>;
} = {
  getStatus,

  /**
   * Convenience wrapper returning a single boolean.
   *
   * Returns `true` only for a `detected` verdict; every other outcome returns
   * `false`, because a boolean has nowhere to put "inconclusive".
   */
  async isSimulator(): Promise<boolean> {
    return (await getStatus()).status === 'detected';
  },
};
