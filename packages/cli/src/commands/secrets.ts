import { parseScanOptions } from '../options.js';
import { rulesInCategories, runScan } from '../scan.js';
import type { CliContext, ExitCodeValue } from '../context.js';

/**
 * `rn-security secrets` — credential detection only.
 *
 * A narrower, faster run for a pre-commit hook or a targeted sweep. It is the
 * same rule as `audit` runs, not a second implementation: a secrets command that
 * disagreed with the full audit would be worse than no secrets command.
 */
export async function secretsCommand(
  argv: readonly string[],
  context: CliContext,
  toolVersion: string
): Promise<ExitCodeValue> {
  const options = parseScanOptions(argv, context);

  return runScan(
    options,
    {
      rules: rulesInCategories(['secrets']),
      emptyNote:
        'No credentials matched. Detection covers published credential formats and ' +
        'sensitively-named values that look random; a secret in an unusual format may not match.',
    },
    context,
    toolVersion
  );
}
