import type { FileKind, Language } from '../types/file.js';

/**
 * What a file is, decided from its path alone.
 *
 * Deciding this before reading anything is what lets the engine skip work
 * cheaply: a rule that only applies to `AndroidManifest.xml` should never cause
 * a single JavaScript file to be read, let alone parsed.
 *
 * Classification is by **path, never by content**. Sniffing content to decide
 * what a file is means reading attacker-controlled bytes to decide how to treat
 * attacker-controlled bytes, and the ordering there only ever gets worse.
 */

const LANGUAGE_BY_EXTENSION: Readonly<Record<string, Language>> = {
  js: 'javascript',
  cjs: 'javascript',
  mjs: 'javascript',
  jsx: 'jsx',
  ts: 'typescript',
  cts: 'typescript',
  mts: 'typescript',
  tsx: 'tsx',
  kt: 'kotlin',
  kts: 'kotlin',
  java: 'java',
  swift: 'swift',
  m: 'objective-c',
  mm: 'objective-cpp',
  h: 'c',
  c: 'c',
  cc: 'cpp',
  cpp: 'cpp',
  hpp: 'cpp',
  xml: 'xml',
  plist: 'plist',
  entitlements: 'plist',
  json: 'json',
  yml: 'yaml',
  yaml: 'yaml',
  gradle: 'gradle',
  rb: 'ruby',
  properties: 'properties',
  sh: 'shell',
  bash: 'shell',
  zsh: 'shell',
  md: 'markdown',
  txt: 'text',
};

/** File names whose role is fixed regardless of where they appear. */
const KIND_BY_BASENAME: Readonly<Record<string, FileKind>> = {
  'AndroidManifest.xml': 'android-manifest',
  'build.gradle': 'gradle-build',
  'build.gradle.kts': 'gradle-build',
  'settings.gradle': 'gradle-build',
  'settings.gradle.kts': 'gradle-build',
  'gradle.properties': 'gradle-properties',
  Podfile: 'podfile',
  'Podfile.lock': 'podfile-lock',
  'package.json': 'package-manifest',
  'package-lock.json': 'lockfile',
  'yarn.lock': 'lockfile',
  'pnpm-lock.yaml': 'lockfile',
  'npm-shrinkwrap.json': 'lockfile',
  'metro.config.js': 'metro-config',
  'metro.config.cjs': 'metro-config',
  'metro.config.ts': 'metro-config',
  'babel.config.js': 'babel-config',
  'babel.config.cjs': 'babel-config',
  '.babelrc': 'babel-config',
  'app.json': 'expo-config',
  'app.config.js': 'expo-config',
  'app.config.ts': 'expo-config',
  'eas.json': 'expo-config',
  '.gitlab-ci.yml': 'ci-config',
  'bitrise.yml': 'ci-config',
  Fastfile: 'ci-config',
};

const TEST_PATH_PATTERN =
  /(^|\/)(__tests__|test|tests|androidTest|instrumentedTest)(\/|$)|\.(test|spec)\.[a-z]+$|Tests?\.(kt|java|swift|m|mm)$/;

const FIXTURE_PATH_PATTERN = /(^|\/)(__fixtures__|__mocks__|fixtures|mocks|snapshots)(\/|$)/;

const EXAMPLE_PATH_PATTERN = /(^|\/)(example|examples|demo|sample|samples|playground)(\/|$)/;

/** Extension of a path, lowercased, without the dot. Empty for dotfiles and extensionless files. */
function extensionOf(path: string): string {
  const basename = path.slice(path.lastIndexOf('/') + 1);
  const dot = basename.lastIndexOf('.');
  if (dot <= 0) {
    return '';
  }
  return basename.slice(dot + 1).toLowerCase();
}

/** Language of a project-relative path. `unknown` when the extension is unrecognised. */
export function languageOf(path: string): Language {
  return LANGUAGE_BY_EXTENSION[extensionOf(path)] ?? 'unknown';
}

/** Whether a path lives in test code. */
export function isTestPath(path: string): boolean {
  return TEST_PATH_PATTERN.test(path);
}

/** Whether a path is a fixture, mock or snapshot. */
export function isFixturePath(path: string): boolean {
  return FIXTURE_PATH_PATTERN.test(path);
}

/** Whether a path lives in an example or demo application. */
export function isExamplePath(path: string): boolean {
  return EXAMPLE_PATH_PATTERN.test(path);
}

/**
 * The role a file plays in a React Native project.
 *
 * Fixture and test classification comes **before** the name table on purpose: a
 * `package.json` inside `__fixtures__` is test data, and treating it as the
 * project's own dependency manifest is how a scanner reports the vulnerabilities
 * it was deliberately given as input.
 */
export function fileKindOf(path: string): FileKind {
  const basename = path.slice(path.lastIndexOf('/') + 1);

  if (isFixturePath(path)) {
    return 'fixture';
  }
  if (isTestPath(path)) {
    return 'test';
  }

  const byName = KIND_BY_BASENAME[basename];
  if (byName !== undefined) {
    return byName;
  }

  if (basename === '.env' || basename.startsWith('.env.')) {
    return 'env-file';
  }
  if (/^\.github\/workflows\//.test(path)) {
    return 'ci-config';
  }
  // Any plist that is not Info.plist still configures an iOS target.
  if (extensionOf(path) === 'plist') {
    return 'ios-plist';
  }
  if (extensionOf(path) === 'entitlements') {
    return 'ios-entitlements';
  }
  if (/(^|\/)res\/xml\/.*network.?security.?config.*\.xml$/i.test(path)) {
    return 'android-network-security-config';
  }
  if (extensionOf(path) === 'md') {
    return 'documentation';
  }

  return languageOf(path) === 'unknown' ? 'other' : 'source';
}

/** Language and role of a project-relative path. */
export function classifyFile(path: string): { language: Language; kind: FileKind } {
  return { language: languageOf(path), kind: fileKindOf(path) };
}
