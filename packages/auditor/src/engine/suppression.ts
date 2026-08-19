import type { AuditorConfig } from '../types/config.js';
import type { SecurityFinding } from '../types/finding.js';

/**
 * Suppression, with a reason required at every layer.
 *
 * False-positive management is mandatory (§43), and a suppression mechanism that
 * accepts silence is worse than none: six months later nobody can tell a
 * considered decision from a `// TODO` that shipped. So every path into this
 * module carries a reason, and a suppression that fails to give one is reported
 * as a **suppression error** and does not take effect. Failing open here is
 * deliberate — a malformed suppression should show you the finding, not hide it.
 *
 * Three layers, in the order they are checked:
 *
 * 1. `rules.disabled` — the rule is switched off for the whole project.
 * 2. `ignore` — a specific finding, by fingerprint. This is the baseline file.
 * 3. inline directives — a specific line, in the source it applies to.
 */

/** A suppression directive found in a source file. */
export interface InlineDirective {
  /** 1-indexed line the directive was written on. */
  readonly line: number;
  /** Rule identifiers it suppresses. */
  readonly ruleIds: readonly string[];
  readonly reason: string;
}

/** A directive that could not be honoured. Reported, and deliberately not applied. */
export interface SuppressionError {
  readonly path: string;
  readonly line: number;
  readonly message: string;
}

export interface InlineScanResult {
  readonly directives: readonly InlineDirective[];
  readonly errors: readonly SuppressionError[];
}

const DIRECTIVE_TOKEN = 'security-audit-ignore';

/**
 * Matches the directive and everything after it on the line.
 *
 * Comment syntax is deliberately not *modelled*, only recognised: `//`, `#`,
 * `/* *\/`, `<!-- -->` and `--` all differ, and a scanner that insists on
 * parsing each language's comments stops working the moment it meets one it was
 * not taught. Requiring the token to follow a comment opener is the cheap middle
 * ground — it means prose that merely mentions the directive is not read as one.
 *
 * The remaining gap is a directive-shaped **string literal**, which still reads
 * as a directive. That is why this package's own test data produces suppression
 * errors when the auditor scans itself: the strings look exactly like the thing
 * they describe.
 */
const DIRECTIVE_PATTERN = new RegExp(
  `(?:^|//|#|/\\*|\\*|<!--|--|;)\\s*${DIRECTIVE_TOKEN}\\s+(.*)$`
);

const REASON_PATTERN = /reason\s*=\s*("([^"]*)"|'([^']*)')/;

/** The shape of a published rule identifier, e.g. `RNSEC-SECRET-001`. */
const RULE_ID_SHAPE = /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$/;

/** Extracts inline suppression directives from a file's lines. */
export function scanInlineDirectives(path: string, lines: readonly string[]): InlineScanResult {
  const directives: InlineDirective[] = [];
  const errors: SuppressionError[] = [];

  lines.forEach((text, index) => {
    const match = DIRECTIVE_PATTERN.exec(text);
    if (match === null) {
      return;
    }

    const line = index + 1;
    const remainder = match[1] ?? '';
    const reasonMatch = REASON_PATTERN.exec(remainder);
    const reason = reasonMatch?.[2] ?? reasonMatch?.[3] ?? '';

    // Rule identifiers are whatever precedes `reason=`.
    const ruleIds = remainder
      .slice(0, reasonMatch?.index ?? remainder.length)
      .split(/[\s,]+/)
      .map((candidate) => candidate.trim())
      .filter((candidate) => candidate.length > 0);

    // Prose that merely mentions the directive is not a directive. Requiring a
    // rule-shaped token or an explicit reason is what separates documentation
    // about suppression from an actual suppression — without it, this project's
    // own documentation reads as a page of malformed directives.
    const looksIntentional =
      ruleIds.some((candidate) => RULE_ID_SHAPE.test(candidate)) || reasonMatch !== null;
    if (!looksIntentional) {
      return;
    }

    if (ruleIds.length === 0) {
      errors.push({
        path,
        line,
        message: `"${DIRECTIVE_TOKEN}" names no rule. Write "${DIRECTIVE_TOKEN} RULE-ID reason=\\"why\\"".`,
      });
      return;
    }

    if (reason.trim().length === 0) {
      errors.push({
        path,
        line,
        message: `"${DIRECTIVE_TOKEN} ${ruleIds.join(' ')}" has no reason, so it was ignored. Write reason="why".`,
      });
      return;
    }

    directives.push({ line, ruleIds, reason: reason.trim() });
  });

  return { directives, errors };
}

/** Why a finding was suppressed. */
export interface Suppression {
  readonly kind: 'rule-disabled' | 'baseline' | 'inline';
  readonly reason: string;
}

/** A finding that was suppressed, kept so a report can account for it. */
export interface SuppressedFinding {
  readonly finding: SecurityFinding;
  readonly suppression: Suppression;
}

/**
 * Decides which findings are suppressed.
 *
 * Inline directives suppress the line they are written on **and the line after**,
 * because both conventions are in use and neither is worth an error message.
 */
export class SuppressionIndex {
  private readonly disabledRules: ReadonlySet<string>;
  private readonly baseline: ReadonlyMap<string, string>;
  private readonly inline: Map<string, readonly InlineDirective[]> = new Map();

  constructor(config: AuditorConfig) {
    this.disabledRules = new Set(config.disabledRules);
    this.baseline = new Map(config.ignore.map((entry) => [entry.fingerprint, entry.reason]));
  }

  /** Registers the directives found in one file. */
  addFileDirectives(path: string, directives: readonly InlineDirective[]): void {
    if (directives.length > 0) {
      this.inline.set(path, directives);
    }
  }

  /** The suppression covering a finding, or `undefined` when it stands. */
  suppressionFor(finding: SecurityFinding): Suppression | undefined {
    if (this.disabledRules.has(finding.ruleId)) {
      return { kind: 'rule-disabled', reason: 'the rule is disabled in configuration' };
    }

    const baselineReason = this.baseline.get(finding.fingerprint);
    if (baselineReason !== undefined) {
      return { kind: 'baseline', reason: baselineReason };
    }

    const directives = this.inline.get(finding.location.path) ?? [];
    const line = finding.location.line;
    if (line === undefined) {
      return undefined;
    }

    const directive = directives.find(
      (candidate) =>
        (candidate.line === line || candidate.line === line - 1) &&
        candidate.ruleIds.includes(finding.ruleId)
    );

    return directive === undefined ? undefined : { kind: 'inline', reason: directive.reason };
  }
}
