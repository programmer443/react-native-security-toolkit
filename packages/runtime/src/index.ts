/**
 * React Native Security Toolkit — public API.
 *
 * Security checks provide defence-in-depth signals and should not be considered
 * a guarantee that a device or application cannot be compromised.
 */

export { SecurityToolkit } from './SecurityToolkit';

export { BiometricSecurity } from './runtime/BiometricSecurity';
export { DebuggerDetection } from './runtime/DebuggerDetection';
export { EmulatorDetection } from './runtime/EmulatorDetection';
export { HookDetection } from './runtime/HookDetection';
export { IntegrityCheck } from './runtime/IntegrityCheck';
export { JailbreakDetection } from './runtime/JailbreakDetection';
export { NetworkSecurity } from './runtime/NetworkSecurity';
export { RootDetection } from './runtime/RootDetection';
export { ScreenSecurity } from './runtime/ScreenSecurity';
export { SimulatorDetection } from './runtime/SimulatorDetection';
export { SecureHardware } from './runtime/SecureHardware';

export { SecurityToolkitError, isSecurityToolkitError } from './internal/errors';
export type { SecurityToolkitErrorCode } from './internal/errors';

export { evaluateRisk } from './risk/riskEngine';
export { RISK_METHODOLOGY_VERSION } from './risk/weights';

export type {
  CheckId,
  IntegrityOptions,
  NativeEngineInfo,
  Platform,
  ResolvedSecurityToolkitOptions,
  SecurityCheckResult,
  SecurityConfidence,
  SecuritySignal,
  PolicyDecision,
  PolicyReason,
  PolicyReasonCode,
  RiskContributor,
  RiskLevel,
  SecurityPolicy,
  SecurityReport,
  SecurityRisk,
  SecurityStatus,
  SecurityToolkitOptions,
  SignalOutcome,
  UnavailableReason,
} from './types';
