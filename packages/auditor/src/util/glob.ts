/**
 * A deliberately small glob matcher.
 *
 * Supports exactly what configuration needs — `**`, `*`, `?` and `{a,b}` —
 * against project-relative POSIX paths. Everything else in a pattern is treated
 * as a literal.
 *
 * Why not a glob library: the auditor's input includes attacker-controlled path
 * names, and glob implementations have a long history of catastrophic
 * backtracking on adversarial patterns. A small, total translation to a regular
 * expression with no nested quantifiers is easier to reason about than a
 * dependency, and this is the only part of the auditor that consumes hostile
 * strings before any size limit has been applied.
 *
 * Semantics:
 * - `**` matches any number of path segments, including none.
 * - `*` and `?` never match `/`.
 * - A pattern containing no `/` is also matched against the final path segment,
 *   so `*.log` behaves the way people expect.
 */

const cache = new Map<string, RegExp>();

/** Characters with meaning in a regular expression but not in a glob. */
function escapeLiteral(text: string): string {
  return text.replace(/[.+^$()|[\]\\]/g, '\\$&');
}

function translate(pattern: string): string {
  let output = '';
  let index = 0;

  while (index < pattern.length) {
    const character = pattern[index];

    if (character === '*') {
      const isGlobstar = pattern[index + 1] === '*';
      if (isGlobstar) {
        // `a/**/b` must also match `a/b`, so the separator is consumed with the
        // globstar rather than left behind as a mandatory slash.
        if (pattern.slice(index + 2, index + 3) === '/') {
          output += '(?:[^/]+/)*';
          index += 3;
        } else {
          output += '.*';
          index += 2;
        }
        continue;
      }
      output += '[^/]*';
      index += 1;
      continue;
    }

    if (character === '?') {
      output += '[^/]';
      index += 1;
      continue;
    }

    if (character === '{') {
      const close = pattern.indexOf('}', index);
      if (close !== -1) {
        const alternatives = pattern.slice(index + 1, close).split(',');
        output += `(?:${alternatives.map(escapeLiteral).join('|')})`;
        index = close + 1;
        continue;
      }
    }

    output += escapeLiteral(character ?? '');
    index += 1;
  }

  return output;
}

function compile(pattern: string): RegExp {
  const cached = cache.get(pattern);
  if (cached !== undefined) {
    return cached;
  }
  const expression = new RegExp(`^${translate(pattern)}$`);
  cache.set(pattern, expression);
  return expression;
}

/** Whether a project-relative POSIX path matches one glob pattern. */
export function matchesGlob(path: string, pattern: string): boolean {
  if (compile(pattern).test(path)) {
    return true;
  }
  // A bare pattern such as `*.log` or `Podfile` is understood as "anywhere".
  if (!pattern.includes('/')) {
    const basename = path.slice(path.lastIndexOf('/') + 1);
    return compile(pattern).test(basename);
  }
  return false;
}

/** Whether a path matches any of the patterns. An empty pattern list matches nothing. */
export function matchesAnyGlob(path: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => matchesGlob(path, pattern));
}

/**
 * Whether a directory can be skipped entirely.
 *
 * Pruning matters for more than speed: descending into `node_modules` on a large
 * project is how a scanner ends up reading a hundred thousand files it was never
 * asked about, and hitting its own limits before reaching the source.
 */
export function isDirectoryExcluded(directory: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => {
    const withoutTrailingGlobstar = pattern.endsWith('/**') ? pattern.slice(0, -3) : pattern;
    return matchesGlob(directory, withoutTrailingGlobstar) || matchesGlob(directory, pattern);
  });
}
