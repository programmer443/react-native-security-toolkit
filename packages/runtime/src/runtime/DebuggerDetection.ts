import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

const getStatus = createCheck('debugger');

/**
 * Debugger detection.
 *
 * Reports whether a debugger is attached to this process, whether another
 * process is ptrace-attached to it, and whether the application itself is built
 * debuggable.
 *
 * @remarks
 * These signals fire constantly during normal development, and that is expected
 * rather than alarming. An application that blocks on a debugger will be
 * impossible to develop against; use `developmentMode` in
 * {@link SecurityToolkit.configure} so a policy can disregard them without the
 * check having to lie about what it observed.
 *
 * @see docs/runtime/debugger-detection.md
 */
export const DebuggerDetection: {
  getStatus(): Promise<SecurityCheckResult>;
  isAttached(): Promise<boolean>;
} = {
  getStatus,

  /**
   * Convenience wrapper returning a single boolean.
   *
   * Returns `true` only when the check reached a `detected` verdict. Every other
   * outcome — including `unknown`, where a probe was blocked and the answer is
   * genuinely not known — returns `false`, because a boolean has nowhere to put
   * "inconclusive". Prefer {@link getStatus} whenever the difference matters,
   * which for a security decision is most of the time.
   */
  async isAttached(): Promise<boolean> {
    return (await getStatus()).status === 'detected';
  },
};
