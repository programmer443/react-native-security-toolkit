import { builtinRules, knowledge } from '@rn-security/auditor';

import { CliError } from '../context.js';
import { parseSafely } from '../options.js';
import type { CliContext, ExitCodeValue } from '../context.js';
import { ExitCode } from '../context.js';

/**
 * `rn-security rules` — what the auditor actually checks.
 *
 * Exists because a rule identifier in a suppression file is meaningless unless
 * you can look it up, and because "what does this tool detect?" should be
 * answerable without reading the source. The JSON form is for tooling that wants
 * to build its own documentation or check a suppression file against the
 * shipped set.
 */
export async function rulesCommand(
  argv: readonly string[],
  context: CliContext
): Promise<ExitCodeValue> {
  const { values, positionals } = parseSafely(argv, {
    format: { type: 'string' },
    category: { type: 'string' },
  });

  if (positionals.length > 0) {
    throw new CliError(
      `"rules" takes no positional arguments. Received "${positionals[0] ?? ''}".`
    );
  }

  const format = (values['format'] as string | undefined) ?? 'console';
  if (format !== 'console' && format !== 'json') {
    throw new CliError(`--format must be console or json for this command. Received "${format}".`);
  }

  const category = values['category'] as string | undefined;
  const selected =
    category === undefined
      ? builtinRules
      : builtinRules.filter((rule) => rule.categories.includes(category as never));

  if (selected.length === 0) {
    throw new CliError(
      `No rules in category "${category ?? ''}". Categories in use: ${[
        ...new Set(builtinRules.flatMap((rule) => rule.categories)),
      ]
        .sort()
        .join(', ')}`
    );
  }

  if (format === 'json') {
    context.stdout(
      `${JSON.stringify(
        {
          knowledgeSnapshot: knowledge.version,
          rules: selected.map((rule) => ({
            id: rule.id,
            name: rule.name,
            description: rule.description,
            severity: rule.severity,
            categories: rule.categories,
            languages: rule.languages,
            fileKinds: rule.fileKinds,
            knowledge: rule.knowledge,
            // Real MASTG test identifiers, so a reader can verify a fix rather
            // than take the tool's word for it.
            verification: (rule.knowledge.maswe ?? []).flatMap((id) =>
              knowledge.mastgTestsFor(id).map((test) => test.id)
            ),
          })),
        },
        null,
        2
      )}\n`
    );
    return ExitCode.Ok;
  }

  const lines: string[] = [
    `${selected.length} rule(s), knowledge snapshot ${knowledge.version}`,
    '',
  ];

  for (const rule of selected) {
    const references = [
      ...(rule.knowledge.cwe ?? []),
      ...(rule.knowledge.maswe ?? []),
      ...(rule.knowledge.masvs ?? []),
    ];
    lines.push(
      `${rule.id}  [${rule.severity}]  ${rule.name}`,
      `  ${rule.description}`,
      `  categories: ${rule.categories.join(', ')}`,
      `  applies to: ${rule.languages.length === 0 ? 'any language' : rule.languages.join(', ')}` +
        ` · ${rule.fileKinds.length === 0 ? 'any file kind' : rule.fileKinds.join(', ')}`,
      ...(references.length === 0 ? [] : [`  standards: ${references.join(', ')}`]),
      `  docs: docs/rules/${rule.id}.md`,
      ''
    );
  }

  context.stdout(`${lines.join('\n')}\n`);
  return ExitCode.Ok;
}
