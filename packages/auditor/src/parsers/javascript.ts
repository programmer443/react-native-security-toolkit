import { parse } from '@babel/parser';
import type { ParserOptions, ParserPlugin } from '@babel/parser';
import crypto from 'node:crypto';

import { LruCache } from '../util/lru.js';
import type { Language } from '../types/file.js';
import type { ParsedFile } from '../types/parse.js';

/**
 * JavaScript-family parsing, with the parser treated as a hazard.
 *
 * `@babel/parser` runs in **error-recovery mode**. A repository that does not
 * compile is not a repository worth skipping — half-finished code is where
 * mistakes live — so a recoverable syntax error yields a usable tree plus a
 * record of what was wrong, rather than nothing at all. Recovery is not total:
 * an error the parser cannot get past produces `parse-failed` carrying the
 * message, never an empty tree, because a rule handed an empty tree would
 * report the file as clean.
 *
 * Two limitations are worth stating plainly rather than burying:
 *
 * - Parsing is **synchronous and cannot be interrupted**. A file crafted to make
 *   the parser take quadratic time would stall the scan, and the only defence in
 *   place is the byte cap applied before parsing. Worker isolation, which would
 *   allow a per-file timeout, is deliberately deferred until there is a second
 *   parser to justify the complexity.
 * - Plugin selection is a guess for `.js`, which in React Native projects may
 *   contain JSX, Flow types, or neither. The recovery is to try the plausible
 *   combinations in order rather than to pick one and mislabel the file.
 */

/** Plugin sets attempted in order. The first that parses without a fatal error wins. */
function pluginCandidates(language: Language): readonly ParserPlugin[][] {
  switch (language) {
    case 'typescript':
      return [['typescript', 'decorators-legacy']];
    case 'tsx':
      return [['typescript', 'jsx', 'decorators-legacy']];
    case 'jsx':
      return [
        ['jsx', 'decorators-legacy'],
        ['jsx', 'flow'],
      ];
    case 'javascript':
      // React Native's own sources are Flow-annotated, and application code
      // frequently is not. Plain JSX first, since it is far more common.
      return [
        ['jsx', 'decorators-legacy'],
        ['jsx', 'flow'],
      ];
    default:
      return [];
  }
}

/** Whether a language has a parser at all. */
export function isParsableLanguage(language: Language): boolean {
  return pluginCandidates(language).length > 0;
}

const BASE_OPTIONS: ParserOptions = {
  sourceType: 'unambiguous',
  errorRecovery: true,
  allowReturnOutsideFunction: true,
  allowSuperOutsideMethod: true,
  allowUndeclaredExports: true,
  attachComment: false,
  ranges: false,
  tokens: false,
};

/**
 * Parse results, cached by content.
 *
 * Keyed on the content hash rather than the path, so the same vendored file
 * appearing in three places is parsed once. Bounded by entries *and* bytes: a
 * hundred cached trees can be a megabyte or a gigabyte depending on what they
 * came from.
 */
const cache = new LruCache<ParsedFile>(256, 64 * 1_048_576);

/** Clears the parse cache. Exposed for tests and long-lived processes. */
export function clearParseCache(): void {
  cache.clear();
}

export interface ParseOptions {
  readonly language: Language;
  /** Files larger than this are not parsed. Rules still receive their text. */
  readonly maxBytes: number;
}

/** Parses a JavaScript-family source file. Never throws. */
export function parseJavaScript(text: string, options: ParseOptions): ParsedFile {
  const candidates = pluginCandidates(options.language);
  if (candidates.length === 0) {
    return { kind: 'unparsed', reason: 'no-parser' };
  }

  const byteLength = Buffer.byteLength(text, 'utf8');
  if (byteLength > options.maxBytes) {
    return {
      kind: 'unparsed',
      reason: 'too-large',
      detail: `${byteLength} bytes exceeds the ${options.maxBytes} byte parse limit`,
    };
  }

  const key = `${options.language}:${crypto.createHash('sha256').update(text).digest('hex')}`;
  const cached = cache.get(key);
  if (cached !== undefined) {
    return cached;
  }

  const result = parseWithFallback(text, candidates);
  // Trees hold references into the source, so the source length is the honest
  // lower bound on what the entry costs.
  cache.set(key, result, byteLength);
  return result;
}

function parseWithFallback(text: string, candidates: readonly ParserPlugin[][]): ParsedFile {
  let lastError = 'unknown parse failure';

  for (let index = 0; index < candidates.length; index += 1) {
    const plugins = candidates[index] ?? [];
    const isLastCandidate = index === candidates.length - 1;

    try {
      const ast = parse(text, { ...BASE_OPTIONS, plugins: [...plugins] });
      const recoveredErrors = (ast.errors ?? []).map((error) =>
        error instanceof Error ? error.message : String(error)
      );

      // A tree recovered from errors is still useful, but if a later plugin set
      // parses the file cleanly, that one describes it better.
      if (recoveredErrors.length === 0 || isLastCandidate) {
        return { kind: 'javascript', ast, recoveredErrors };
      }
      lastError = recoveredErrors[0] ?? lastError;
    } catch (error: unknown) {
      lastError = error instanceof Error ? error.message : String(error);
    }
  }

  return { kind: 'unparsed', reason: 'parse-failed', detail: lastError };
}
