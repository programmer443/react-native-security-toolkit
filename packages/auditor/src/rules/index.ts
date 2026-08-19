import { appTransportSecurityRule } from './ios/appTransportSecurity.js';
import { promptInjectionRule } from './ai/promptInjection.js';
import { cleartextTrafficRule } from './network/cleartextTraffic.js';
import { disabledTlsValidationRule } from './network/disabledTlsValidation.js';
import { dynamicCodeExecutionRule } from './reactNative/dynamicCodeExecution.js';
import {
  exportedComponentRule,
  manifestConfigurationRule,
} from './android/manifestConfiguration.js';
import { hardcodedSecretRule } from './secrets/hardcodedSecret.js';
import { insecureRandomnessRule } from './crypto/insecureRandomness.js';
import { insecureStorageRule } from './storage/insecureStorage.js';
import { sensitiveLoggingRule } from './logging/sensitiveLogging.js';
import { unsafeWebViewRule } from './webview/unsafeWebView.js';
import { untrustedDependencyRule } from './dependencies/untrustedDependency.js';
import { unvalidatedDeepLinkRule } from './deeplinks/unvalidatedDeepLink.js';
import { weakCryptographyRule } from './crypto/weakCryptography.js';
import type { SecurityRule } from '../types/rule.js';

/**
 * The rules shipped with the auditor.
 *
 * Ordered by the value they carry rather than alphabetically, which is also the
 * order they were written in: secrets and credentials first, then the storage
 * and transport of those credentials, then the platform surfaces that leak them.
 *
 * Every rule here is documented in `docs/rules/<ID>.md` and has tests covering
 * four cases: a true positive, a true negative, an edge case, and the false
 * positive the rule most plausibly produces.
 */
export const builtinRules: readonly SecurityRule[] = [
  hardcodedSecretRule,
  insecureStorageRule,
  weakCryptographyRule,
  insecureRandomnessRule,
  cleartextTrafficRule,
  disabledTlsValidationRule,
  unsafeWebViewRule,
  unvalidatedDeepLinkRule,
  sensitiveLoggingRule,
  manifestConfigurationRule,
  exportedComponentRule,
  appTransportSecurityRule,
  untrustedDependencyRule,
  dynamicCodeExecutionRule,
  promptInjectionRule,
];

export { appTransportSecurityRule } from './ios/appTransportSecurity.js';
export { promptInjectionRule } from './ai/promptInjection.js';
export { cleartextTrafficRule } from './network/cleartextTraffic.js';
export { disabledTlsValidationRule } from './network/disabledTlsValidation.js';
export { dynamicCodeExecutionRule } from './reactNative/dynamicCodeExecution.js';
export {
  exportedComponentRule,
  manifestConfigurationRule,
} from './android/manifestConfiguration.js';
export { hardcodedSecretRule } from './secrets/hardcodedSecret.js';
export { insecureRandomnessRule } from './crypto/insecureRandomness.js';
export { insecureStorageRule } from './storage/insecureStorage.js';
export { sensitiveLoggingRule } from './logging/sensitiveLogging.js';
export { unsafeWebViewRule } from './webview/unsafeWebView.js';
export { untrustedDependencyRule } from './dependencies/untrustedDependency.js';
export { unvalidatedDeepLinkRule } from './deeplinks/unvalidatedDeepLink.js';
export { weakCryptographyRule } from './crypto/weakCryptography.js';
