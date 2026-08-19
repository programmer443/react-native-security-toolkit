import crypto from 'node:crypto';

/**
 * Stable identity for a finding.
 *
 * **Line numbers are deliberately excluded.** A fingerprint that moves when an
 * import is added at the top of a file invalidates every suppression below it,
 * and a baseline that has to be regenerated after every edit is a baseline
 * nobody keeps. The trade is real and accepted: two identical problems in the
 * same structural context of the same file collapse into one finding.
 *
 * The inputs are the rule, the file, the structural context a rule chose to
 * supply (an enclosing function, a configuration key path) and the normalised
 * evidence text.
 */

export interface FingerprintInput {
  readonly ruleId: string;
  /** Project-relative POSIX path. An absolute path would make fingerprints machine-specific. */
  readonly path: string;
  readonly structuralContext?: string;
  readonly evidence: readonly string[];
}

/**
 * Collapses whitespace and trims.
 *
 * Case is **preserved**: lowercasing would merge two distinct credentials that
 * differ only in case, which is exactly the pair a secrets rule must keep apart.
 */
function normalise(text: string): string {
  return text.replace(/[\t\n\r ]+/g, ' ').trim();
}

/** Builds the fingerprint. Same inputs, same value, on every machine and every run. */
export function createFingerprint(input: FingerprintInput): string {
  const parts = [
    input.ruleId,
    input.path,
    input.structuralContext ?? '',
    input.evidence.map(normalise).join(' '),
  ];

  // NUL as the separator: it cannot occur in a rule identifier or a path, and
  // binary files are never scanned, so two different input tuples cannot
  // concatenate into the same digest input.
  return crypto.createHash('sha256').update(parts.join('\u0000')).digest('hex').slice(0, 32);
}
