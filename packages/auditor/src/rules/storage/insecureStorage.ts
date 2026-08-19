import {
  calleeName,
  enclosingContext,
  memberName,
  staticString,
  walk,
} from '../../analysis/ast.js';
import { buildFinding, evidence, nodeLocation, snippetOf } from '../../analysis/findings.js';
import { describeSensitiveKind, sensitiveKindOf } from '../../analysis/sensitivity.js';
import type * as t from '@babel/types';

import type { RawFinding } from '../../types/finding.js';
import type { RuleContext, SecurityRule } from '../../types/rule.js';

/**
 * RNSEC-STORAGE-001 — sensitive data written to unencrypted local storage.
 *
 * §34 is blunt about the failure mode here: *do not declare every AsyncStorage
 * use vulnerable*. AsyncStorage is the normal way a React Native app persists
 * preferences, and it is entirely appropriate for them. What is not appropriate
 * is a refresh token in it.
 *
 * So the rule looks at **what is being stored**, from two directions: the key
 * the value is filed under, and the name of the variable holding it. Storage
 * APIs that are already encrypted — Keychain, Keystore-backed stores,
 * `expo-secure-store`, `react-native-encrypted-storage`, `EncryptedSharedPreferences`
 * — are recognised and never reported.
 */

interface StorageSink {
  readonly callee: string;
  readonly label: string;
  /** Argument index of the key, and of the value. */
  readonly keyArgument: number;
  readonly valueArgument: number;
}

const JS_SINKS: readonly StorageSink[] = [
  { callee: 'AsyncStorage.setItem', label: 'AsyncStorage', keyArgument: 0, valueArgument: 1 },
  { callee: 'AsyncStorage.mergeItem', label: 'AsyncStorage', keyArgument: 0, valueArgument: 1 },
  { callee: 'localStorage.setItem', label: 'localStorage', keyArgument: 0, valueArgument: 1 },
  { callee: 'sessionStorage.setItem', label: 'sessionStorage', keyArgument: 0, valueArgument: 1 },
  { callee: 'storage.set', label: 'MMKV', keyArgument: 0, valueArgument: 1 },
  { callee: 'storage.setString', label: 'MMKV', keyArgument: 0, valueArgument: 1 },
  { callee: 'mmkv.set', label: 'MMKV', keyArgument: 0, valueArgument: 1 },
  { callee: 'RNFS.writeFile', label: 'the filesystem', keyArgument: 0, valueArgument: 1 },
  {
    callee: 'FileSystem.writeAsStringAsync',
    label: 'the filesystem',
    keyArgument: 0,
    valueArgument: 1,
  },
];

/**
 * Storage that is encrypted by the platform.
 *
 * Recognising these matters as much as recognising the unsafe ones: a rule that
 * cannot tell `SecureStore` from `AsyncStorage` punishes the developer who did
 * the right thing.
 */
const SECURE_SINK_MARKERS: readonly string[] = [
  'securestore',
  'encryptedstorage',
  'keychain',
  'react-native-keychain',
  'expo-secure-store',
  'encryptedsharedpreferences',
  'sensitiveinfo',
];

const KNOWLEDGE = {
  cwe: ['CWE-312', 'CWE-922'],
  masvs: ['MASVS-STORAGE-1'],
  maswe: ['MASWE-0001'],
  mappingConfidence: 'high',
} as const;

const IMPACT =
  'Unencrypted application storage is readable by anyone with the device unlocked and a file ' +
  'manager on a rooted or jailbroken handset, by a device backup, and by forensic tooling. Stored ' +
  'credentials survive the session that created them.';

const EXPLOITABILITY =
  'Requires physical or backup access to the device, or a second vulnerability that grants file ' +
  'access. No cryptographic work is involved: the data is in plaintext.';

const REMEDIATION =
  'Store credentials in hardware-backed storage — the iOS Keychain or the Android Keystore, via ' +
  '`expo-secure-store`, `react-native-keychain` or `EncryptedSharedPreferences`. Better still, ' +
  'keep long-lived credentials off the device entirely and hold only a short-lived session token.';

export const insecureStorageRule: SecurityRule = {
  id: 'RNSEC-STORAGE-001',
  name: 'Sensitive data in unencrypted storage',
  description:
    'A value whose name or storage key indicates a credential, token or personal data is written ' +
    'to storage that the platform does not encrypt.',
  severity: 'high',
  categories: ['storage'],
  languages: [],
  fileKinds: [],
  // A code example in prose is not a defect.
  excludeFileKinds: ['documentation'],
  knowledge: KNOWLEDGE,

  detect(context: RuleContext): readonly RawFinding[] {
    if (usesSecureStorage(context)) {
      return detectNative(context);
    }
    return [...detectJavaScript(context), ...detectNative(context)];
  },
};

/** Whether the file imports a storage API that is encrypted by the platform. */
function usesSecureStorage(context: RuleContext): boolean {
  const head = context.text.slice(0, 4_000).toLowerCase();
  return SECURE_SINK_MARKERS.some((marker) => head.includes(marker));
}

function detectJavaScript(context: RuleContext): RawFinding[] {
  const findings: RawFinding[] = [];

  walk(context.parsed, ({ node, ancestors }) => {
    if (node.type !== 'CallExpression') {
      return;
    }
    const callee = calleeName(node);
    if (callee === undefined) {
      return;
    }
    const sink = JS_SINKS.find((candidate) => candidate.callee === callee);
    if (sink === undefined) {
      return;
    }

    const keyNode = node.arguments[sink.keyArgument] as t.Node | undefined;
    const valueNode = node.arguments[sink.valueArgument] as t.Node | undefined;

    const keyName = keyNode === undefined ? undefined : staticString(keyNode);
    const valueName =
      valueNode === undefined
        ? undefined
        : valueNode.type === 'Identifier'
          ? valueNode.name
          : memberName(valueNode);

    const keyKind = keyName === undefined ? undefined : sensitiveKindOf(keyName);
    const valueKind = valueName === undefined ? undefined : sensitiveKindOf(valueName);
    const kind = keyKind ?? valueKind;
    if (kind === undefined) {
      return;
    }

    const subject = keyKind !== undefined ? keyName : valueName;
    const location = nodeLocation(node);
    const snippet = snippetOf(context.lines, location.line);
    const structural = enclosingContext(ancestors);

    findings.push(
      buildFinding({
        ruleId: 'RNSEC-STORAGE-001',
        title: `${describeSensitiveKind(kind)} written to ${sink.label}`,
        description:
          `"${subject}" names ${describeSensitiveKind(kind)}, and ${sink.label} stores values in ` +
          'plaintext on the device.',
        severity: 'high',
        confidence: keyKind !== undefined && valueKind !== undefined ? 'high' : 'medium',
        categories: ['storage'],
        path: context.file.path,
        ...location,
        evidence: [
          evidence('storage-sink', `Written through ${callee}`, {
            ...location,
            ...(snippet === undefined ? {} : { snippet }),
          }),
          evidence('sensitive-name', `"${subject}" names ${describeSensitiveKind(kind)}`, location),
        ],
        impact: IMPACT,
        exploitability: EXPLOITABILITY,
        remediation: REMEDIATION,
        ...(snippet === undefined ? {} : { codeSnippet: snippet }),
        ...(structural === undefined ? {} : { structuralContext: structural }),
        knowledge: KNOWLEDGE,
      })
    );
  });

  return findings;
}

/** Native preference stores, matched textually. */
const NATIVE_SINKS: readonly { pattern: RegExp; label: string; secure: RegExp }[] = [
  {
    pattern: /\.(?:putString|putInt|putBoolean|putLong|putFloat)\s*\(/,
    label: 'SharedPreferences',
    secure: /EncryptedSharedPreferences/,
  },
  {
    pattern: /UserDefaults\.standard\.(?:set|setValue)\s*\(/,
    label: 'UserDefaults',
    secure: /Keychain|kSecClass/,
  },
];

function detectNative(context: RuleContext): RawFinding[] {
  const language = context.file.language;
  const isNative = language === 'kotlin' || language === 'java' || language === 'swift';
  if (!isNative) {
    return [];
  }

  const findings: RawFinding[] = [];

  context.lines.forEach((text, index) => {
    const sink = NATIVE_SINKS.find((candidate) => candidate.pattern.test(text));
    if (sink === undefined || sink.secure.test(context.text)) {
      return;
    }

    const names = text.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
    const quoted = text.match(/["']([^"']+)["']/g)?.map((value) => value.slice(1, -1)) ?? [];
    const candidate = [...quoted, ...names].find((name) => sensitiveKindOf(name) !== undefined);
    if (candidate === undefined) {
      return;
    }

    const kind = sensitiveKindOf(candidate);
    if (kind === undefined) {
      return;
    }

    const line = index + 1;
    findings.push(
      buildFinding({
        ruleId: 'RNSEC-STORAGE-001',
        title: `${describeSensitiveKind(kind)} written to ${sink.label}`,
        description:
          `"${candidate}" names ${describeSensitiveKind(kind)}, and ${sink.label} stores values in ` +
          'plaintext on the device.',
        severity: 'high',
        confidence: 'medium',
        categories: ['storage'],
        path: context.file.path,
        line,
        evidence: [
          evidence('storage-sink', `Written through ${sink.label}`, {
            line,
            snippet: text.trim().slice(0, 200),
          }),
          evidence('sensitive-name', `"${candidate}" names ${describeSensitiveKind(kind)}`, {
            line,
          }),
        ],
        impact: IMPACT,
        exploitability: EXPLOITABILITY,
        remediation: REMEDIATION,
        structuralContext: sink.label,
        knowledge: KNOWLEDGE,
      })
    );
  });

  return findings;
}
