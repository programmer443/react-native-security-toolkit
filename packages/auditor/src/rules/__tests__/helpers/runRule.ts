import { RuleRegistry } from '../../../engine/ruleRegistry.js';
import { classifyFile } from '../../../classification/classify.js';
import { isParsableLanguage, parseJavaScript } from '../../../parsers/javascript.js';
import type { RawFinding } from '../../../types/finding.js';
import type { ParsedFile } from '../../../types/parse.js';
import type { RuleContext, SecurityRule } from '../../../types/rule.js';

/**
 * Runs one rule against a file described in the test.
 *
 * Builds the same context the engine builds — classification, parse, lines — so
 * that a rule test exercises the rule exactly as a scan would, without needing a
 * project on disk.
 */
export async function runRule(
  rule: SecurityRule,
  path: string,
  text: string,
  projectFiles: readonly string[] = []
): Promise<readonly RawFinding[]> {
  const { language, kind } = classifyFile(path);

  let parsed: ParsedFile | undefined;
  if (isParsableLanguage(language)) {
    parsed = parseJavaScript(text, { language, maxBytes: 1_000_000 });
  }

  const file = { absolutePath: `/project/${path}`, path, sizeBytes: text.length, language, kind };

  // The engine decides whether a rule applies to a file before calling it, so
  // the helper does too. Without this a test could "pass" against a rule the
  // engine would never have run — which is how an exclusion silently stops
  // working.
  if (new RuleRegistry([rule]).rulesFor(file).length === 0) {
    return [];
  }

  const context: RuleContext = {
    file,
    text,
    lines: text.split(/\r?\n/),
    project: { files: [path, ...projectFiles] },
    ...(parsed === undefined ? {} : { parsed }),
  };

  return [...(await rule.detect(context))];
}

/** Convenience: the rule ids present in a result. */
export function titles(findings: readonly RawFinding[]): readonly string[] {
  return findings.map((finding) => finding.title);
}
