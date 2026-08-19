/**
 * Deciding whether a string *looks* like a secret.
 *
 * Entropy alone is a bad secret detector: a minified bundle, a base64 image, a
 * UUID and a git SHA all score high, and flagging them is how a secrets scanner
 * ends up producing a thousand findings nobody reads (§34: "do not flag every
 * random-looking string").
 *
 * So entropy here is never used on its own. It is one input; the name the value
 * is assigned to, its shape, and a list of obviously-benign forms are the
 * others.
 */

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }

  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/** Values that look random but are not secrets. */
const BENIGN_SHAPES: readonly RegExp[] = [
  // UUID, including the nil UUID and version-4 forms.
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  // Git object identifier.
  /^[0-9a-f]{40}$/i,
  // Semantic version, date, or dotted numeric identifier.
  /^[0-9][0-9.]*$/,
  // A URL is not a secret, though what is *in* one may be.
  /^[a-z][a-z0-9+.-]*:\/\//i,
  // File paths and package specifiers.
  /^[./~@][\w./@-]*$/,
  // CSS colours and hex constants.
  /^#[0-9a-f]{3,8}$/i,
  // Data URIs: large, high-entropy, and not credentials.
  /^data:/i,
  // Placeholder values that exist to be replaced.
  /^(?:x{4,}|\*{4,}|\.{3,}|<[^>]+>|\$\{[^}]*\}|%[sd]|changeme|placeholder|example|dummy|sample|test|todo)$/i,
];

/** Whether a value has a shape known not to be a secret. */
export function hasBenignShape(value: string): boolean {
  return BENIGN_SHAPES.some((pattern) => pattern.test(value.trim()));
}

/** Character-class heuristics used alongside entropy. */
export interface ValueShape {
  readonly length: number;
  readonly entropy: number;
  readonly hasUpper: boolean;
  readonly hasLower: boolean;
  readonly hasDigit: boolean;
  readonly hasSymbol: boolean;
  /** True when the value looks like base64 or hexadecimal of a credible length. */
  readonly looksEncoded: boolean;
  /** True when the value is made of dictionary-ish words — prose, not a key. */
  readonly looksLikeProse: boolean;
}

export function describeShape(value: string): ValueShape {
  return {
    length: value.length,
    entropy: shannonEntropy(value),
    hasUpper: /[A-Z]/.test(value),
    hasLower: /[a-z]/.test(value),
    hasDigit: /[0-9]/.test(value),
    hasSymbol: /[^A-Za-z0-9]/.test(value),
    looksEncoded: /^[A-Za-z0-9+/=_-]{16,}$/.test(value) || /^[0-9a-f]{32,}$/i.test(value),
    looksLikeProse: /\s/.test(value.trim()) && /^[\p{L}\p{N}\s.,!?'"-]+$/u.test(value),
  };
}

/**
 * Whether a value is random-looking enough to be credential material.
 *
 * The thresholds are deliberately conservative. A secrets rule that fires on
 * `"en-GB"` or `"react-native"` trains people to ignore it, and a missed secret
 * that a *named* pattern would have caught is the lesser cost — the named
 * patterns are the primary detector, and this is the backstop.
 */
export function looksHighEntropy(value: string, minimumLength = 20): boolean {
  const trimmed = value.trim();
  if (trimmed.length < minimumLength || hasBenignShape(trimmed)) {
    return false;
  }

  const shape = describeShape(trimmed);
  if (shape.looksLikeProse) {
    return false;
  }

  // Kebab- and snake-case identifiers are dense enough to clear an entropy
  // threshold — `security-audit-ignore` scores 3.8 — and are never secrets.
  // Every constant name in a codebase looks like this.
  if (/^[a-z0-9]+(?:[-_.][a-z0-9]+)+$/.test(trimmed)) {
    return false;
  }

  // Encoded material is dense but has a smaller alphabet, so it scores lower
  // than mixed text of the same randomness; it gets its own threshold.
  if (shape.looksEncoded) {
    return shape.entropy >= 3.5;
  }

  const classes = [shape.hasUpper, shape.hasLower, shape.hasDigit, shape.hasSymbol].filter(
    Boolean
  ).length;
  return shape.entropy >= 4.2 && classes >= 3;
}
