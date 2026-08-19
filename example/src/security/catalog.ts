/**
 * Display copy for every check, status and reason code.
 *
 * All of it is derived from `docs/runtime/*.md`, and deliberately kept in one
 * place: the wording around these results is a correctness concern, not a
 * cosmetic one. "Potential root indicators detected" and "device is rooted" are
 * different claims, and only one of them is true. Sprinkling that wording
 * through twelve components is how the wrong version eventually ships.
 *
 * The `kind` field is the distinction most security UIs get wrong. Half of these
 * checks look for an adversary; the other half report a capability. Painting
 * both with the same red badge tells a user that their phone lacking StrongBox
 * is the same class of event as a Frida agent in their process.
 */

import {
  BiometricSecurity,
  DebuggerDetection,
  EmulatorDetection,
  HookDetection,
  IntegrityCheck,
  JailbreakDetection,
  NetworkSecurity,
  RootDetection,
  ScreenSecurity,
  SecureHardware,
  SimulatorDetection,
  type CheckId,
  type PolicyReasonCode,
  type RiskLevel,
  type SecurityCheckResult,
  type SecurityConfidence,
  type SecurityStatus,
  type SignalOutcome,
  type UnavailableReason,
} from 'react-native-security-toolkit';
import {
  BugIcon,
  CheckCircleIcon,
  CpuIcon,
  CrosshairIcon,
  EyeOffIcon,
  FingerprintIcon,
  GlobeIcon,
  HelpCircleIcon,
  MinusCircleIcon,
  MonitorIcon,
  SealCheckIcon,
  ShieldAlertIcon,
  SmartphoneIcon,
  TerminalIcon,
  UnlockIcon,
  XCircleIcon,
  type IconComponent,
} from '../icons';

/**
 * What a check is fundamentally doing.
 *
 * - `threat` — looking for an adversary. `detected` is bad news.
 * - `environment` — describing where the app runs. Neither good nor bad.
 * - `capability` — reporting what the platform offers. `detected` means a
 *   weakness indicator fired, not that an attack was found.
 */
export type CheckKind = 'threat' | 'environment' | 'capability';

export interface CheckMeta {
  readonly title: string;
  /** One line, shown under the title in lists. */
  readonly tagline: string;
  /** What the check actually looks at. Two sentences at most. */
  readonly summary: string;
  /** The honest limitation. Always shown on the detail screen; never hidden. */
  readonly caveat: string;
  readonly icon: IconComponent;
  readonly kind: CheckKind;
  readonly platforms: readonly ('android' | 'ios')[];
  /** Documentation path inside the repository, shown for further reading. */
  readonly docs: string;
}

export const CHECKS: Readonly<Record<CheckId, CheckMeta>> = Object.freeze({
  root: {
    title: 'Root detection',
    tagline: 'Android · bootloader, su, Magisk, Zygisk',
    summary:
      'Looks for device modification associated with root: an unlocked bootloader, a su binary, root management apps, overlaid system partitions, permissive SELinux, and Magisk or Zygisk-style injection artefacts.',
    caveat:
      'A developer with an unlocked bootloader, a custom-ROM user and someone actively instrumenting your app produce overlapping signals. Every indicator can be defeated by an attacker who controls the device.',
    icon: TerminalIcon,
    kind: 'threat',
    platforms: ['android'],
    docs: 'docs/runtime/root-detection.md',
  },
  jailbreak: {
    title: 'Jailbreak detection',
    tagline: 'iOS · rootful and rootless artefacts',
    summary:
      'Looks for iOS modification: filesystem artefacts from both classic and rootless jailbreaks, sandbox escape, injected libraries, the dyld insertion environment variable, and package-manager URL schemes.',
    caveat:
      'Rootless jailbreaks relocate their filesystem under a prefix such as /var/jb, so path lists copied from the Cydia era detect nothing while looking thorough. Indicators are evidence, not proof.',
    icon: UnlockIcon,
    kind: 'threat',
    platforms: ['ios'],
    docs: 'docs/runtime/jailbreak-detection.md',
  },
  debugger: {
    title: 'Debugger detection',
    tagline: 'Attachment, ptrace and build posture',
    summary:
      'Distinguishes a JDWP debugger, another process ptrace-attached to this one, a debuggable build, and device posture such as developer options or ADB being enabled.',
    caveat:
      'A debugger is a development tool, not an attack. These signals fire constantly during normal development — which is why development mode drops them from the risk score rather than hiding them.',
    icon: BugIcon,
    kind: 'threat',
    platforms: ['android', 'ios'],
    docs: 'docs/runtime/debugger-detection.md',
  },
  emulator: {
    title: 'Emulator detection',
    tagline: 'Android · build identity, device nodes, hardware profile',
    summary:
      'Reports whether the app runs on an Android emulator, a virtualised image or a cloud device rather than retail hardware, from build identity, emulator-only device nodes and hardware profile.',
    caveat:
      'Running under emulation is not a compromise. CI runs on emulators, QA runs on device farms, and Play Games runs Android apps on desktops. On its own this is a poor reason to block anyone.',
    icon: MonitorIcon,
    kind: 'environment',
    platforms: ['android'],
    docs: 'docs/runtime/emulator-detection.md',
  },
  simulator: {
    title: 'Simulator detection',
    tagline: 'iOS · simulated or physical device',
    summary:
      'Reports whether the process runs on the iOS Simulator. Other checks depend on it: jailbreak detection reports unavailable there rather than producing a false positive on every development run.',
    caveat:
      'Running on a simulator is not a compromise — it is where nearly all development happens. This check is, unusually for this toolkit, genuinely reliable.',
    icon: SmartphoneIcon,
    kind: 'environment',
    platforms: ['ios'],
    docs: 'docs/runtime/simulator-detection.md',
  },
  hooks: {
    title: 'Hook detection',
    tagline: 'Instrumentation agents, hooking frameworks, symbol redirection',
    summary:
      'Looks for dynamic instrumentation mapped into the process, managed-code hooking frameworks on the call stack or in memory, and standard library symbols resolving inside the wrong library.',
    caveat:
      'This check is adversarial in a way the others are not: a framework that can hook your app can hook the code detecting it. What these signals buy is cost — "attach and go" becomes "attach, then hide".',
    icon: CrosshairIcon,
    kind: 'threat',
    platforms: ['android', 'ios'],
    docs: 'docs/runtime/hook-detection.md',
  },
  integrity: {
    title: 'Application integrity',
    tagline: 'Signing certificate, installer, package identity',
    summary:
      'Checks whether the running application is the one you published: signing certificate against a fingerprint you declared, the installing package, the package or bundle identifier, and the install location.',
    caveat:
      'Genuine integrity assurance comes from Play Integrity or App Attest verified on your server. These signals catch sideloading and re-signing cheaply and locally; they inform a server-side decision rather than replacing one. Three of the four need configuration to mean anything.',
    icon: SealCheckIcon,
    kind: 'threat',
    platforms: ['android', 'ios'],
    docs: 'docs/runtime/integrity.md',
  },
  secureHardware: {
    title: 'Secure hardware',
    tagline: 'Keystore, StrongBox, Secure Enclave, attestation',
    summary:
      'Reports whether keys generated by this application are hardware-backed, whether a dedicated secure element such as StrongBox is present, and whether hardware-backed key attestation is available.',
    caveat:
      'A capability report, not a threat detection. A device having a hardware-backed keystore says nothing about whether this application uses it, or uses it correctly.',
    icon: CpuIcon,
    kind: 'capability',
    platforms: ['android', 'ios'],
    docs: 'docs/runtime/secure-hardware.md',
  },
  biometrics: {
    title: 'Biometric capability',
    tagline: 'Strong biometrics, enrolment, device credential',
    summary:
      'Reports whether strong (Class 3) biometric authentication is usable, whether a biometric is enrolled, and whether any device credential is set at all.',
    caveat:
      'No biometric data is read, stored or exposed by this check, and none is available to it. An unenrolled device is not an insecure device: a PIN and no fingerprint is a perfectly good choice.',
    icon: FingerprintIcon,
    kind: 'capability',
    platforms: ['android', 'ios'],
    docs: 'docs/runtime/biometrics.md',
  },
  network: {
    title: 'Network security',
    tagline: 'Cleartext policy, proxy, VPN, user CAs',
    summary:
      "Reports this application's own transport configuration and the device's network posture: whether cleartext HTTP is permitted, whether a proxy is configured, whether a VPN transport is active, and whether user-added certificate authorities are installed.",
    caveat:
      'A mobile application cannot reliably detect an interception attack — a competent attacker on the network path leaves no trace visible from inside the process. This is configuration and posture, never MITM detection.',
    icon: GlobeIcon,
    kind: 'capability',
    platforms: ['android', 'ios'],
    docs: 'docs/runtime/network-security.md',
  },
  screen: {
    title: 'Screen security',
    tagline: 'Capture protection state',
    summary:
      'Reports whether screen capture protection is currently applied, and is the one place the toolkit will change device state on request.',
    caveat:
      'The platforms genuinely differ. On Android FLAG_SECURE is real prevention. On iOS there is no public API to prevent a screenshot — only detection is possible. A feature matrix ticking both is making a false claim about one.',
    icon: EyeOffIcon,
    kind: 'capability',
    platforms: ['android', 'ios'],
    docs: 'docs/runtime/screen-security.md',
  },
});

/**
 * The focused single-check API, keyed by id.
 *
 * `checkAll()` is what a real app calls at startup, but the per-check modules are
 * public API too, so the detail screen re-runs a check through its own module.
 * That keeps both code paths exercised by the example rather than only the
 * aggregate one.
 */
export const CHECK_MODULES: Readonly<Record<CheckId, () => Promise<SecurityCheckResult>>> =
  Object.freeze({
    root: RootDetection.getStatus,
    jailbreak: JailbreakDetection.getStatus,
    debugger: DebuggerDetection.getStatus,
    emulator: EmulatorDetection.getStatus,
    simulator: SimulatorDetection.getStatus,
    hooks: HookDetection.getStatus,
    integrity: IntegrityCheck.getStatus,
    secureHardware: SecureHardware.getStatus,
    biometrics: BiometricSecurity.getStatus,
    network: NetworkSecurity.getStatus,
    screen: ScreenSecurity.getStatus,
  });

/** Order used everywhere a list of checks is shown. Threats first. */
export const CHECK_ORDER: readonly CheckId[] = Object.freeze([
  'root',
  'jailbreak',
  'hooks',
  'integrity',
  'debugger',
  'emulator',
  'simulator',
  'secureHardware',
  'biometrics',
  'network',
  'screen',
]);

export interface StatusMeta {
  /** Short word for a pill. */
  readonly label: string;
  /** What this status means, phrased for the check's `kind`. */
  readonly explain: (kind: CheckKind) => string;
  readonly icon: IconComponent;
}

export const STATUS: Readonly<Record<SecurityStatus, StatusMeta>> = Object.freeze({
  secure: {
    label: 'Clear',
    explain: (kind) =>
      kind === 'capability'
        ? 'The check ran and found no weakness indicators. It does not mean the application uses the platform correctly.'
        : 'The check ran to completion and no indicators fired. It is not proof that the device is unmodified.',
    icon: CheckCircleIcon,
  },
  detected: {
    label: 'Indicators',
    explain: (kind) =>
      kind === 'capability'
        ? 'One or more weakness indicators fired. The platform offers less protection here than an app handling sensitive material would want.'
        : 'One or more indicators fired. Weigh the signals below rather than treating this as a verdict.',
    icon: ShieldAlertIcon,
  },
  unknown: {
    label: 'Inconclusive',
    explain: () =>
      'The check ran but could not reach a verdict — a probe was blocked or unreadable. Inconclusive is not the same as clear, and must never be read as one.',
    icon: HelpCircleIcon,
  },
  unavailable: {
    label: 'Unavailable',
    explain: () =>
      'The check did not run here. The reason below says whether that is expected or something the app still owes the toolkit.',
    icon: MinusCircleIcon,
  },
  error: {
    label: 'Error',
    explain: () =>
      'The check failed unexpectedly. The toolkit reports this as a result rather than throwing, so one broken check cannot take down a screen.',
    icon: XCircleIcon,
  },
});

export const UNAVAILABLE_REASONS: Readonly<Record<UnavailableReason, string>> = Object.freeze({
  'platform-not-supported': 'Belongs to the other platform. Expected here; no action needed.',
  'permission-denied': 'The OS denied a permission or query this check depends on.',
  'api-level-too-low': "This device's OS version predates the API the check needs.",
  'not-configured': 'Needs configuration the application has not supplied yet.',
  'disabled-by-config': 'Switched off through SecurityToolkit.configure().',
  'hardware-not-present': 'The required hardware is absent from this device.',
  simulator: 'Cannot be evaluated meaningfully on a simulator.',
});

export const OUTCOME_LABEL: Readonly<Record<SignalOutcome, string>> = Object.freeze({
  detected: 'Fired',
  indeterminate: 'Inconclusive',
  'not-detected': 'Clear',
});

export const CONFIDENCE_LABEL: Readonly<Record<SecurityConfidence, string>> = Object.freeze({
  low: 'Low confidence',
  medium: 'Medium confidence',
  high: 'High confidence',
});

export const CONFIDENCE_HINT =
  'Confidence describes the strength of the evidence, not how serious the finding is. A single filesystem hit is low confidence even though root is severe.';

export interface RiskLevelMeta {
  readonly label: string;
  /** Advisory phrased as guidance to the application, never as a verdict. */
  readonly advice: string;
}

export const RISK_LEVELS: Readonly<Record<RiskLevel, RiskLevelMeta>> = Object.freeze({
  minimal: {
    label: 'Minimal',
    advice: 'No meaningful indicators. Nothing here argues against normal operation.',
  },
  low: {
    label: 'Low',
    advice: 'Weak or ambiguous indicators only. Worth logging; rarely worth acting on alone.',
  },
  medium: {
    label: 'Medium',
    advice: 'Real indicators present. A sensible point to require re-authentication or step down.',
  },
  high: {
    label: 'High',
    advice: 'Corroborated indicators. Consider gating payments, KYC and other sensitive flows.',
  },
  critical: {
    label: 'Critical',
    advice: 'Strong, corroborated indicators. Treat this session as untrusted for sensitive work.',
  },
});

export const POLICY_REASONS: Readonly<Record<PolicyReasonCode, string>> = Object.freeze({
  ROOT_DETECTED: 'Root indicators',
  JAILBREAK_DETECTED: 'Jailbreak indicators',
  DEBUGGER_DETECTED: 'Debugger indicators',
  HOOKING_DETECTED: 'Hooking indicators',
  INTEGRITY_FAILED: 'Integrity mismatch',
  RISK_LEVEL_EXCEEDED: 'Risk level exceeded',
  SECURE_HARDWARE_UNAVAILABLE: 'Secure hardware unavailable',
  STRONG_BIOMETRICS_UNAVAILABLE: 'Strong biometrics unavailable',
});

/** The disclaimer that belongs on any screen showing a verdict. */
export const DEFENCE_IN_DEPTH_NOTE =
  'Runtime security checks are defence-in-depth signals. They should not be treated as a guarantee that a device or application cannot be compromised.';
