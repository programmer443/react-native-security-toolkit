import { createCheck } from './createCheck';
import type { SecurityCheckResult } from '../types';

/**
 * Hook and instrumentation detection.
 *
 * Reports indicators that this process is being instrumented: dynamic
 * instrumentation agents mapped into memory or running as injected threads,
 * managed-code hooking frameworks, and standard library symbols that resolve
 * inside libraries other than the ones expected to provide them.
 *
 * @remarks
 * This check is adversarial in a way the others are not. An attacker running a
 * hooking framework can, by definition, modify the code performing the
 * detection — including this check. **Detection is not guaranteed and cannot
 * be.** What these signals buy is cost: they raise the effort required from
 * "attach and go" to "attach, then hide".
 *
 * Only this process is inspected. No other process is examined, and no network
 * probing is performed.
 *
 * @see docs/runtime/hook-detection.md
 */
export const HookDetection: {
  getStatus(): Promise<SecurityCheckResult>;
} = {
  getStatus: createCheck('hooks'),
};
