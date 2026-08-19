import { createCheck } from './createCheck';
import { getNativeModule } from '../internal/nativeModule';
import type { SecurityCheckResult } from '../types';

/**
 * Screen capture protection.
 *
 * @remarks
 * The platforms differ here in a way that matters, and the toolkit does not
 * flatten it:
 *
 * - **Android** — `FLAG_SECURE` is genuine *prevention*. The platform blocks
 *   screenshots and recordings of a protected window.
 * - **iOS** — there is **no public API to prevent a screenshot**. Only detection
 *   is possible. Until the iOS engine lands, `enableProtection()` resolves to
 *   `false` there rather than pretending to have done something.
 *
 * `FLAG_SECURE` is also **per-window**. Dialogs and React Native modals create
 * their own windows, and protection applied to an activity does not extend to
 * them. The toolkit re-applies the flag across activity lifecycle events so it
 * survives rotation and recreation, but it cannot reach windows it does not own.
 *
 * @see docs/runtime/screen-security.md
 */
export const ScreenSecurity: {
  getStatus(): Promise<SecurityCheckResult>;
  enableProtection(): Promise<boolean>;
  disableProtection(): Promise<boolean>;
} = {
  getStatus: createCheck('screen'),

  /**
   * Applies screen capture protection.
   *
   * @returns whether the change reached a live window. `false` means the intent
   * was recorded and will apply once a window exists — during a cold start, for
   * example — or that the platform cannot honour it. Check {@link getStatus} if
   * you need to know which.
   */
  async enableProtection(): Promise<boolean> {
    return getNativeModule().setScreenProtection(true);
  },

  /** Removes screen capture protection. See {@link enableProtection}. */
  async disableProtection(): Promise<boolean> {
    return getNativeModule().setScreenProtection(false);
  },
};
