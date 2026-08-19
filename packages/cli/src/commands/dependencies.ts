import { parseScanOptions } from '../options.js';
import { rulesInCategories, runScan } from '../scan.js';
import type { CliContext, ExitCodeValue } from '../context.js';

/**
 * `rn-security dependencies` — dependency resolution checks.
 *
 * **This is not a vulnerability scanner, and the command says so.** It reports
 * what a manifest can establish on its own: dependencies whose resolution is not
 * deterministic, or not authenticated. Advisory data belongs behind a provider
 * interface fetched at scan time (§38), and claiming coverage this command does
 * not have would be worse than the gap.
 */
export async function dependenciesCommand(
  argv: readonly string[],
  context: CliContext,
  toolVersion: string
): Promise<ExitCodeValue> {
  const options = parseScanOptions(argv, context);

  return runScan(
    options,
    {
      rules: rulesInCategories(['dependencies']),
      emptyNote:
        'Every dependency resolves deterministically over an authenticated transport. ' +
        'This command does not check dependencies against vulnerability advisories — ' +
        'run `npm audit`, `pnpm audit` or your platform scanner for that.',
    },
    context,
    toolVersion
  );
}
