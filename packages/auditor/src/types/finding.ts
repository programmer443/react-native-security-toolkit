import type { KnowledgeRefs } from './rule.js';

/**
 * The finding model produced by the static auditor.
 *
 * A finding has to answer ten questions to be worth reporting at all (§40):
 * what is wrong, where, why it is dangerous, how confident we are, what the
 * impact and exploitability are, which standards it maps to, how to fix it, and
 * how to verify the fix. Anything less produces a report a developer cannot act
 * on, which is the normal failure mode of static analysis tools.
 */

/** Impact-and-exploitability band. Computed by the engine, not declared by a rule alone. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** How much the evidence supports the claim. Independent of {@link Severity}. */
export type Confidence = 'very-low' | 'low' | 'medium' | 'high' | 'very-high';

/** Rule categories, mirroring §26. */
export type Category =
  | 'secrets'
  | 'storage'
  | 'cryptography'
  | 'network'
  | 'authentication'
  | 'authorization'
  | 'webview'
  | 'deep-links'
  | 'logging'
  | 'privacy'
  | 'android'
  | 'ios'
  | 'react-native'
  | 'dependencies'
  | 'configuration'
  | 'serialization'
  | 'native-bridge'
  /** Content in the repository aimed at an AI model reading it. */
  | 'ai';

/**
 * How a finding was established.
 *
 * `ai` is called out separately and deliberately: §81 requires an AI-derived
 * finding to be identifiable as such rather than presented alongside
 * deterministic evidence as if it carried the same weight.
 */
export type FindingSource =
  'deterministic' | 'ast' | 'dependency' | 'configuration' | 'ai' | 'hybrid';

/** A single piece of supporting evidence. */
export interface SecurityEvidence {
  /** What kind of observation this is, e.g. `matched-pattern`, `ast-node`, `entropy`. */
  readonly kind: string;
  /** Human-readable statement of what was observed. */
  readonly description: string;
  /**
   * The observed text, already truncated and — for secrets — masked by the rule.
   *
   * Rules are responsible for never putting a live credential in here: a report
   * file is far more widely shared than the source file it came from.
   */
  readonly snippet?: string;
  readonly line?: number;
  readonly column?: number;
}

/**
 * A reference into a security standard.
 *
 * The identifier is authoritative; the title is looked up from the versioned
 * knowledge snapshot rather than written by a rule author, so a report cannot
 * quietly disagree with the standard it cites (§33).
 */
export interface StandardReference {
  readonly id: string;
  /** Official title, from the knowledge snapshot. Absent if the snapshot lacks one. */
  readonly title?: string;
  /**
   * How sure we are that this mapping is right.
   *
   * `low` is an honest answer and §32 requires it over a confident-looking
   * fabrication. A mapping that cannot be justified is omitted entirely.
   */
  readonly mappingConfidence: 'low' | 'medium' | 'high';
}

/** Links out to documentation. */
export interface SecurityReference {
  readonly title: string;
  readonly url: string;
}

/** Where in the project a finding lives. */
export interface FindingLocation {
  /** Project-relative POSIX path. Never absolute: reports travel between machines. */
  readonly path: string;
  readonly line?: number;
  readonly column?: number;
  readonly endLine?: number;
  readonly endColumn?: number;
}

/** One reported problem. */
export interface SecurityFinding {
  /** Unique per occurrence. Derived from the fingerprint, so it is stable across runs. */
  readonly id: string;
  /** The rule that produced it, e.g. `RNSEC-SECRET-001`. */
  readonly ruleId: string;

  readonly title: string;
  readonly description: string;

  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly categories: readonly Category[];

  readonly location: FindingLocation;
  readonly codeSnippet?: string;

  readonly evidence: readonly SecurityEvidence[];

  /** Resolved standards references. Populated by the engine from validated identifiers. */
  readonly cwe?: readonly StandardReference[];
  readonly masvs?: readonly StandardReference[];
  readonly maswe?: readonly StandardReference[];
  readonly mastg?: readonly StandardReference[];

  readonly impact: string;
  readonly exploitability: string;

  readonly remediation: string;
  readonly secureExample?: string;
  readonly references?: readonly SecurityReference[];

  readonly sources: readonly FindingSource[];

  /**
   * Stable identity of this finding, excluding line numbers.
   *
   * Line-number-free on purpose: adding an import at the top of a file must not
   * invalidate every suppression below it, or a baseline file becomes unusable
   * within a week.
   */
  readonly fingerprint: string;

  /**
   * Set when the engine adjusted the rule's declared severity, with the reason.
   *
   * Recorded rather than applied silently, so a downgraded finding can be
   * audited instead of quietly disappearing from a report.
   */
  readonly severityAdjustment?: {
    readonly from: Severity;
    readonly to: Severity;
    readonly reason: string;
  };
}

/** A finding a rule wants to report, before the engine adds identity and context. */
export type RawFinding = Omit<
  SecurityFinding,
  | 'id'
  | 'fingerprint'
  | 'sources'
  | 'severity'
  | 'severityAdjustment'
  | 'cwe'
  | 'masvs'
  | 'maswe'
  | 'mastg'
> & {
  /** Base severity. The engine may adjust it for context, recording why. */
  readonly severity: Severity;
  readonly sources?: readonly FindingSource[];
  /**
   * Standards identifiers for *this* finding, when a rule reports more than one
   * kind of problem and they map differently.
   *
   * Identifiers only, and they must be a subset of the identifiers the rule
   * declares — those are validated against the knowledge snapshot when the rule
   * is registered. Omit to inherit the rule's own mapping.
   */
  readonly knowledge?: KnowledgeRefs;
  /**
   * Structural context for fingerprinting, e.g. an enclosing function name or a
   * configuration key path. Optional, but a rule that supplies it gets
   * fingerprints that survive code movement within a file.
   */
  readonly structuralContext?: string;
};
