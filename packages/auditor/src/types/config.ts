import type { Severity } from './finding.js';

/** Bounds the auditor refuses to exceed, whatever the repository contains. */
export interface ScanLimits {
  /** Files larger than this are skipped and recorded. */
  readonly maxFileBytes: number;
  /** Upper bound on files offered to the rule engine. */
  readonly maxFiles: number;
  /** Upper bound on total bytes read from the project. */
  readonly maxTotalBytes: number;
  /** Directory nesting depth. Guards recursive and generated trees. */
  readonly maxDepth: number;
  /** Files larger than this are not parsed, though rules still see their text. */
  readonly maxParseBytes: number;
  /** Files analysed concurrently. */
  readonly concurrency: number;
  /** Wall-clock budget for the whole scan, in milliseconds. */
  readonly timeoutMs: number;
}

/** Adjusts a rule's severity, optionally only under certain paths. */
export interface RuleOverride {
  /** Rule identifier the override applies to. */
  readonly rule: string;
  readonly severity?: Severity;
  /** Glob patterns; when present, the override applies only to matching files. */
  readonly paths?: readonly string[];
}

/**
 * A finding suppressed by identity.
 *
 * A reason is **required**. An unexplained suppression is indistinguishable from
 * a mistake six months later, and §43 is explicit about demanding one.
 */
export interface SuppressionEntry {
  readonly fingerprint: string;
  readonly reason: string;
}

/**
 * Configuration as a project author writes it.
 *
 * Every field is optional; the defaults are chosen to scan a normal React Native
 * project usefully without configuration.
 */
export interface AuditorOptions {
  /**
   * Reporting profile.
   *
   * - `minimal` — only `high` and above are reported.
   * - `standard` — `low` and above are reported. The default.
   * - `strict` — everything, including `info`.
   */
  readonly profile?: 'minimal' | 'standard' | 'strict';
  /** Glob patterns to scan. Empty or absent means the whole project. */
  readonly include?: readonly string[];
  /** Glob patterns to skip, applied after {@link include}. */
  readonly exclude?: readonly string[];
  readonly rules?: {
    readonly disabled?: readonly string[];
    readonly overrides?: readonly RuleOverride[];
  };
  readonly ignore?: readonly SuppressionEntry[];
  readonly severity?: {
    /** Severity at which a CI run should fail. Reporting only; the engine never exits. */
    readonly failOn?: Severity;
    /** Findings below this severity are dropped from the report. */
    readonly minimum?: Severity;
  };
  readonly limits?: Partial<ScanLimits>;
  /**
   * AI-assisted analysis. **Disabled by default and off in this phase** (§28/§54).
   *
   * Accepted here so that a configuration file written against a later version
   * does not fail to load, and so the resolved configuration can state plainly
   * that AI was not used.
   */
  readonly ai?: {
    readonly enabled?: boolean;
  };
}

/** Fully resolved configuration, with defaults applied. */
export interface AuditorConfig {
  readonly profile: 'minimal' | 'standard' | 'strict';
  readonly include: readonly string[];
  readonly exclude: readonly string[];
  readonly disabledRules: readonly string[];
  readonly ruleOverrides: readonly RuleOverride[];
  readonly ignore: readonly SuppressionEntry[];
  readonly failOn: Severity;
  readonly minimumSeverity: Severity;
  readonly limits: ScanLimits;
  readonly ai: { readonly enabled: boolean };
}
