/**
 * Shapes of the versioned security knowledge snapshot.
 *
 * The snapshot is a **lookup table of identifiers**, not a copy of the
 * standards: identifiers, titles and the mappings upstream itself declares.
 * Nothing here paraphrases OWASP or MITRE prose, because a rule that quotes a
 * standard is a rule that drifts from it silently.
 */

/** One MASVS v2 control, e.g. `MASVS-STORAGE-1`. */
export interface MasvsControl {
  readonly id: string;
  /** Owning category, e.g. `MASVS-STORAGE`. */
  readonly group: string;
  readonly groupTitle: string;
  /** The control statement, as published. */
  readonly title: string;
}

/** One MASWE weakness, with the mappings it declares upstream. */
export interface MasweWeakness {
  readonly id: string;
  readonly title: string;
  /** MASVS v2 controls this weakness maps to. */
  readonly masvs: readonly string[];
  /** CWE identifiers this weakness maps to. */
  readonly cwe: readonly string[];
  readonly platforms: readonly string[];
}

/** One MASTG test, and the weakness it verifies. */
export interface MastgTest {
  readonly id: string;
  readonly title: string;
  readonly platform: string;
  /** MASWE identifier, or an empty string when upstream declares none. */
  readonly weakness: string;
  /**
   * `beta` tests live under `tests-beta/` upstream and may still be renumbered,
   * which is worth knowing before pinning a rule to one.
   */
  readonly status: string;
}

/** One CWE entry: identifier and official name. */
export interface CweEntry {
  readonly id: string;
  readonly name: string;
}

/** A dated, immutable capture of all four standards. */
export interface KnowledgeSnapshot {
  /** Snapshot version, e.g. `2026.1`. Not the version of any single standard. */
  readonly version: string;
  readonly cwe: readonly CweEntry[];
  readonly masvs: readonly MasvsControl[];
  readonly maswe: readonly MasweWeakness[];
  readonly mastg: readonly MastgTest[];
}
