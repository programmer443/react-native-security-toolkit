import type { Category, RawFinding } from './finding.js';
import type { DiscoveredFile, FileKind, Language } from './file.js';
import type { ParsedFile } from './parse.js';

/**
 * Standard identifiers a rule maps to. Identifiers only — no prose (§33).
 *
 * Every identifier is checked against the versioned knowledge snapshot when the
 * rule is registered, so a mistyped or invented reference fails immediately
 * rather than appearing in a report nobody can verify.
 */
export interface KnowledgeRefs {
  /** CWE identifiers, e.g. `CWE-798`. */
  readonly cwe?: readonly string[];
  /** MASVS v2 controls, e.g. `MASVS-STORAGE-1`. */
  readonly masvs?: readonly string[];
  /** MASWE weaknesses, e.g. `MASWE-0004`. */
  readonly maswe?: readonly string[];
  /** MASTG tests that verify the weakness, e.g. `MASTG-TEST-0200`. */
  readonly mastg?: readonly string[];
  /**
   * How sure the rule author is that this mapping is right.
   *
   * §32 asks for uncertain mappings to be marked rather than dressed up.
   * Defaults to `medium`; use `low` when the fit is arguable, and omit the
   * mapping entirely when it is a guess.
   */
  readonly mappingConfidence?: 'low' | 'medium' | 'high';
}

/**
 * What a rule is given, and the limit of what it can reach.
 *
 * A rule receives text, a parse result and metadata. It has **no filesystem
 * write access, no network access and no process access**, because the
 * repository under analysis is treated as hostile (§44) and a rule is the part
 * of the system that touches hostile input most directly.
 */
export interface RuleContext {
  readonly file: DiscoveredFile;
  /** Full file text, already size-capped by discovery. */
  readonly text: string;
  /** Lines of {@link text}, 0-indexed, provided so rules do not each re-split it. */
  readonly lines: readonly string[];
  /** Parse result for the file, when its language has a parser. */
  readonly parsed?: ParsedFile;
  /** Facts about the project as a whole, e.g. whether it is an Expo app. */
  readonly project: ProjectContext;
}

/** Project-level facts a rule may need to judge context. */
export interface ProjectContext {
  /** Project-relative POSIX paths of every discovered file. Read-only. */
  readonly files: readonly string[];
  /** Parsed `package.json` of the project root, when present and valid JSON. */
  readonly packageJson?: Readonly<Record<string, unknown>>;
}

/**
 * One detection technique.
 *
 * Rules are pure functions of their context: same input, same findings. That is
 * what makes them independently unit-testable (§26) and what keeps a report
 * reproducible in CI.
 */
export interface SecurityRule {
  /** Stable identifier, e.g. `RNSEC-STORAGE-001`. Never renumbered once published (§78). */
  readonly id: string;
  readonly name: string;
  readonly description: string;
  /** Base severity. The engine may adjust it for context. */
  readonly severity: RawFinding['severity'];
  readonly categories: readonly Category[];
  /** Languages this rule applies to. Empty means "any language". */
  readonly languages: readonly Language[];
  /** File kinds this rule applies to. Empty means "any kind". */
  readonly fileKinds: readonly FileKind[];
  /**
   * File kinds this rule must never run on, even when `fileKinds` is open.
   *
   * Documentation is the case that matters: a README explaining that MD5 is
   * broken contains the string `MD5`, and a rule that reports it is reporting
   * the warning rather than the weakness.
   */
  readonly excludeFileKinds?: readonly FileKind[];
  readonly knowledge: KnowledgeRefs;
  /** Must not throw. A rule that throws is reported as a rule error, not a finding. */
  detect(context: RuleContext): Promise<readonly RawFinding[]> | readonly RawFinding[];
}
