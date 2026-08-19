import { buildFinding, evidence } from '../../analysis/findings.js';
import { elementsNamed, scanXml } from '../../analysis/xml.js';
import type { RawFinding } from '../../types/finding.js';
import type { KnowledgeRefs, RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-ANDROID-MANIFEST-001 — application-level manifest settings that weaken
 * the app.
 *
 * Each of these is a single attribute, and each is a decision someone made:
 *
 * - `android:debuggable="true"` — attaches a debugger to a release build, which
 *   means reading memory and stepping through the application on any device.
 * - `android:allowBackup="true"` — application data is included in device
 *   backups, from where it can be extracted with `adb backup` on older devices
 *   or read out of a cloud backup.
 * - `android:usesCleartextTraffic="true"` — re-enables plain HTTP, which the
 *   platform has disallowed by default since Android 9.
 * - `android:testOnly="true"` — the package can only be installed through
 *   `adb install -t`, and is a build that was never meant to ship.
 *
 * Gradle can override `debuggable` per build type, so a manifest value is what
 * the manifest asks for, not necessarily what the release APK ends up with. The
 * finding says so rather than overclaiming.
 */

const DEBUG_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-489'],
  masvs: ['MASVS-RESILIENCE-4'],
  maswe: ['MASWE-0063'],
  mappingConfidence: 'high',
};

const BACKUP_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-312'],
  masvs: ['MASVS-STORAGE-2'],
  maswe: ['MASWE-0006'],
  mappingConfidence: 'high',
};

const CLEARTEXT_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-319'],
  masvs: ['MASVS-NETWORK-1'],
  maswe: ['MASWE-0026'],
  mappingConfidence: 'high',
};

interface ManifestFlag {
  readonly attribute: string;
  readonly unsafeValue: string;
  readonly title: string;
  readonly detail: string;
  readonly severity: RawFinding['severity'];
  readonly confidence: RawFinding['confidence'];
  readonly impact: string;
  readonly exploitability: string;
  readonly remediation: string;
  readonly knowledge: KnowledgeRefs;
}

const FLAGS: readonly ManifestFlag[] = [
  {
    attribute: 'android:debuggable',
    unsafeValue: 'true',
    title: 'Application is marked debuggable',
    detail:
      '`android:debuggable="true"` allows a debugger to attach to the installed application on any ' +
      'device. Note that Gradle sets this per build type, so a release build may override it — ' +
      'confirm against the built APK.',
    severity: 'high',
    confidence: 'medium',
    impact:
      'A debugger can read and modify process memory, inspect variables holding decrypted data, and ' +
      'step through authentication logic on a device the attacker controls.',
    exploitability: 'Requires physical or ADB access to a device with the application installed.',
    remediation:
      'Remove the attribute from the manifest and let the build type decide. Verify the release ' +
      'artefact with `aapt dump badging` rather than trusting the source manifest.',
    knowledge: DEBUG_KNOWLEDGE,
  },
  {
    attribute: 'android:allowBackup',
    unsafeValue: 'true',
    title: 'Application data is included in device backups',
    detail:
      '`android:allowBackup="true"` lets the platform copy application data into device and cloud ' +
      'backups, outside the application sandbox.',
    severity: 'medium',
    confidence: 'high',
    impact:
      'Anything in application storage — tokens, caches, databases — can be extracted from a ' +
      'backup, on a device the user may no longer control.',
    exploitability:
      'Requires access to a backup: ADB on an older device, or the account the backup is attached to.',
    remediation:
      'Set `android:allowBackup="false"`, or keep backups and exclude sensitive files with ' +
      '`android:dataExtractionRules` (API 31+) and `android:fullBackupContent`. Credentials belong ' +
      'in the Keystore, which is never backed up.',
    knowledge: BACKUP_KNOWLEDGE,
  },
  {
    attribute: 'android:usesCleartextTraffic',
    unsafeValue: 'true',
    title: 'Cleartext HTTP is enabled application-wide',
    detail:
      '`android:usesCleartextTraffic="true"` re-enables plain HTTP, which the platform blocks by ' +
      'default from Android 9 onwards.',
    severity: 'high',
    confidence: 'high',
    impact:
      'Any request the application makes over HTTP can be read and modified by anything on the ' +
      'network path.',
    exploitability: 'A network position is sufficient; no access to the device is needed.',
    remediation:
      'Remove the attribute and serve every endpoint over HTTPS. If one host genuinely requires ' +
      'cleartext, scope it to that host in a Network Security Config instead of enabling it ' +
      'everywhere.',
    knowledge: CLEARTEXT_KNOWLEDGE,
  },
  {
    attribute: 'android:testOnly',
    unsafeValue: 'true',
    title: 'Application is marked test-only',
    detail:
      '`android:testOnly="true"` marks a build that can only be installed with `adb install -t`. It ' +
      'is a development artefact and should never reach a store listing.',
    severity: 'low',
    confidence: 'high',
    impact:
      'The package is not a shippable build; distributing it signals a broken release process.',
    exploitability: 'Not directly exploitable.',
    remediation: 'Remove the attribute and build release artefacts from a release build type.',
    knowledge: DEBUG_KNOWLEDGE,
  },
];

export const manifestConfigurationRule: SecurityRule = {
  id: 'RNSEC-ANDROID-MANIFEST-001',
  name: 'Insecure AndroidManifest configuration',
  description:
    'The application element enables debugging, backups, cleartext traffic or test-only ' +
    'installation.',
  severity: 'high',
  categories: ['android', 'configuration'],
  languages: ['xml'],
  fileKinds: ['android-manifest'],
  knowledge: {
    cwe: ['CWE-489', 'CWE-312', 'CWE-319'],
    masvs: ['MASVS-RESILIENCE-4', 'MASVS-STORAGE-2', 'MASVS-NETWORK-1'],
    maswe: ['MASWE-0063', 'MASWE-0006', 'MASWE-0026'],
    mappingConfidence: 'high',
  },

  detect(context: RuleContext): readonly RawFinding[] {
    const elements = scanXml(context.text);
    const findings: RawFinding[] = [];

    for (const application of elementsNamed(elements, 'application')) {
      for (const flag of FLAGS) {
        const value = application.attributes[flag.attribute];
        if (value !== flag.unsafeValue) {
          continue;
        }

        findings.push(
          buildFinding({
            ruleId: 'RNSEC-ANDROID-MANIFEST-001',
            title: flag.title,
            description: flag.detail,
            severity: flag.severity,
            confidence: flag.confidence,
            categories: ['android', 'configuration'],
            path: context.file.path,
            line: application.line,
            evidence: [
              evidence('manifest-attribute', `${flag.attribute}="${flag.unsafeValue}"`, {
                line: application.line,
              }),
            ],
            impact: flag.impact,
            exploitability: flag.exploitability,
            remediation: flag.remediation,
            structuralContext: flag.attribute,
            knowledge: flag.knowledge,
          })
        );
      }
    }

    return findings;
  },
};

/**
 * RNSEC-ANDROID-MANIFEST-002 — a component exported without a permission.
 *
 * §36 warns against blindly flagging every exported component, and it is right
 * to: the launcher activity is exported by necessity, and plenty of components
 * are exported on purpose so other applications can use them.
 *
 * What this rule reports is the *unguarded* case — exported, with no permission
 * required — and it treats the launcher as what it is. Content providers are
 * called out separately because an exported provider without a permission
 * exposes data, not just an entry point.
 */
const COMPONENT_KNOWLEDGE: KnowledgeRefs = {
  cwe: ['CWE-926'],
  masvs: ['MASVS-PLATFORM-1'],
  maswe: ['MASWE-0018'],
  mappingConfidence: 'high',
};

const COMPONENT_ELEMENTS: readonly string[] = [
  'activity',
  'activity-alias',
  'service',
  'receiver',
  'provider',
];

export const exportedComponentRule: SecurityRule = {
  id: 'RNSEC-ANDROID-MANIFEST-002',
  name: 'Exported component without a permission',
  description:
    'A component is exported to other applications without requiring a permission, so any ' +
    'installed application can reach it.',
  severity: 'medium',
  categories: ['android', 'authorization'],
  languages: ['xml'],
  fileKinds: ['android-manifest'],
  knowledge: COMPONENT_KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    const elements = scanXml(context.text);
    const findings: RawFinding[] = [];

    for (const element of elements) {
      if (!COMPONENT_ELEMENTS.includes(element.name)) {
        continue;
      }
      if (element.attributes['android:exported'] !== 'true') {
        continue;
      }
      if (
        element.attributes['android:permission'] !== undefined ||
        element.attributes['android:readPermission'] !== undefined ||
        element.attributes['android:writePermission'] !== undefined
      ) {
        continue;
      }

      const name = element.attributes['android:name'] ?? '(unnamed)';
      // The launcher activity must be exported; reporting it is noise.
      if (isLauncher(context.text, element.line)) {
        continue;
      }

      const isProvider = element.name === 'provider';
      findings.push(
        buildFinding({
          ruleId: 'RNSEC-ANDROID-MANIFEST-002',
          title: `Exported ${element.name} without a permission: ${name}`,
          description:
            `\`${name}\` is exported and requires no permission, so any application on the device ` +
            'can send it an intent' +
            (isProvider ? ' or query it for data.' : '.'),
          severity: isProvider ? 'high' : 'medium',
          confidence: 'medium',
          categories: ['android', 'authorization'],
          path: context.file.path,
          line: element.line,
          evidence: [
            evidence('manifest-attribute', 'android:exported="true"', { line: element.line }),
            evidence('manifest-attribute', 'No android:permission is declared', {
              line: element.line,
            }),
          ],
          impact: isProvider
            ? 'Another application can read or write the data this provider exposes, subject only to ' +
              'whatever checks the provider implements itself.'
            : 'Another application can start this component with input of its choosing, reaching ' +
              'whatever the component does with that input.',
          exploitability:
            'Requires a malicious or compromised application on the same device. No permissions are ' +
            'needed to send an intent.',
          remediation:
            'If the component is not meant for other applications, set `android:exported="false"`. ' +
            'If it is, require a signature-level permission and validate everything in the incoming ' +
            'intent as untrusted input.',
          structuralContext: `${element.name}:${name}`,
          knowledge: COMPONENT_KNOWLEDGE,
        })
      );
    }

    return findings;
  },
};

/**
 * Whether the component starting at this line declares the launcher intent.
 *
 * The element scanner is flat, so the check is textual: look ahead a bounded
 * window for the LAUNCHER category before the next component begins.
 */
function isLauncher(source: string, line: number): boolean {
  const lines = source.split(/\r?\n/);
  // Everything after the component's own opening line, up to the next component.
  const following = lines.slice(line, line + 15).join('\n');
  const nextComponent = following.search(
    /<(?:activity|activity-alias|service|receiver|provider)[\s>]/
  );
  const scope = nextComponent === -1 ? following : following.slice(0, nextComponent);
  return scope.includes('android.intent.category.LAUNCHER');
}
