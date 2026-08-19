/** Languages and file roles the auditor recognises. */

/**
 * Source language of a file.
 *
 * Rules declare the languages they apply to so the engine can skip files
 * cheaply, before reading or parsing anything.
 */
export type Language =
  | 'javascript'
  | 'jsx'
  | 'typescript'
  | 'tsx'
  | 'kotlin'
  | 'java'
  | 'swift'
  | 'objective-c'
  | 'objective-cpp'
  | 'c'
  | 'cpp'
  | 'xml'
  | 'plist'
  | 'json'
  | 'yaml'
  | 'gradle'
  | 'ruby'
  | 'properties'
  | 'shell'
  | 'markdown'
  | 'text'
  | 'unknown';

/**
 * What a file *is* to a React Native project, as opposed to what language it is
 * written in.
 *
 * A rule about exported Android components cares that a file is the manifest,
 * not that it happens to be XML — and a rule about lockfiles must not run over
 * every JSON file in the repository.
 */
export type FileKind =
  | 'source'
  | 'test'
  | 'fixture'
  | 'android-manifest'
  | 'android-network-security-config'
  | 'gradle-build'
  | 'gradle-properties'
  | 'ios-plist'
  | 'ios-entitlements'
  | 'podfile'
  | 'podfile-lock'
  | 'package-manifest'
  | 'lockfile'
  | 'metro-config'
  | 'babel-config'
  | 'expo-config'
  | 'ci-config'
  | 'env-file'
  | 'documentation'
  | 'other';

/** A file the discovery pass decided to offer to the rule engine. */
export interface DiscoveredFile {
  /** Absolute path on this machine. Never put in a report. */
  readonly absolutePath: string;
  /** Project-relative POSIX path. This is what reports and fingerprints use. */
  readonly path: string;
  readonly sizeBytes: number;
  readonly language: Language;
  readonly kind: FileKind;
}

/** Why discovery declined to offer a path to the rule engine. */
export type SkipReason =
  | 'excluded-by-config'
  | 'not-included-by-config'
  | 'symbolic-link'
  | 'outside-project-root'
  | 'too-large'
  | 'binary'
  | 'unreadable'
  | 'file-limit-reached'
  | 'total-size-limit-reached'
  | 'depth-limit-reached';

/**
 * A path discovery skipped, and why.
 *
 * Every skip is recorded. A scanner that silently drops files reports "no
 * findings" for a directory it never opened, which reads exactly like a clean
 * bill of health (§44).
 */
export interface SkippedPath {
  readonly path: string;
  readonly reason: SkipReason;
  readonly detail?: string;
}
