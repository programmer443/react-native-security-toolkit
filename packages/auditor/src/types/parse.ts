import type * as t from '@babel/types';

/** Result of parsing a JavaScript-family file. */
export interface JavaScriptParse {
  readonly kind: 'javascript';
  readonly ast: t.File;
  /**
   * Syntax errors recovered from during parsing.
   *
   * Parsing runs in error-recovery mode: a file with a syntax error still yields
   * a usable tree, because a repository that does not compile is exactly the kind
   * of repository worth auditing.
   */
  readonly recoveredErrors: readonly string[];
}

/** A file whose language has no parser yet; rules see the text only. */
export interface UnparsedFile {
  readonly kind: 'unparsed';
  readonly reason: 'no-parser' | 'too-large' | 'parse-failed';
  readonly detail?: string;
}

export type ParsedFile = JavaScriptParse | UnparsedFile;
