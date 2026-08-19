import { Platform as RNPlatform } from 'react-native';
import NativeSecurityToolkit, { type Spec } from '../specs/NativeSecurityToolkit';
import { SecurityToolkitError } from './errors';

/**
 * Access to the native module, with a seam for tests.
 *
 * `TurboModuleRegistry.get` is resolved once at import and may be `null` when
 * the package is installed but the native side is not linked — a common state
 * after adding the dependency without rebuilding. Surfacing that as an
 * actionable error beats a `null is not an object` crash deep inside a check.
 */

let override: Spec | null | undefined;

const LINK_HINT =
  'The react-native-security-toolkit native module is not linked. ' +
  'Rebuild the application (Android: rebuild the app; iOS: run `pod install`, then rebuild). ' +
  'A Metro reload alone is not enough after adding a native dependency.';

/** Returns the native module, or throws a {@link SecurityToolkitError} explaining why it is absent. */
export function getNativeModule(): Spec {
  const module = override !== undefined ? override : NativeSecurityToolkit;
  if (module == null) {
    throw new SecurityToolkitError('NATIVE_MODULE_UNAVAILABLE', LINK_HINT);
  }
  return module;
}

/** Whether the native module is present. Never throws. */
export function isNativeModuleAvailable(): boolean {
  return (override !== undefined ? override : NativeSecurityToolkit) != null;
}

/** The platform the toolkit is running on, or `null` on unsupported platforms. */
export function currentPlatform(): 'android' | 'ios' | null {
  if (RNPlatform.OS === 'android' || RNPlatform.OS === 'ios') {
    return RNPlatform.OS;
  }
  return null;
}

/**
 * Test seam. Pass a stub to install it, or `undefined` to restore the real module.
 *
 * @internal Not part of the public API and not exported from the package root.
 */
export function __setNativeModuleForTesting(module: Spec | null | undefined): void {
  override = module;
}
