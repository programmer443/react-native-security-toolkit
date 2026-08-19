import { builtinRules } from '@rn-security/auditor';

import { parseScanOptions } from '../options.js';
import { runScan } from '../scan.js';
import type { CliContext, ExitCodeValue } from '../context.js';

/**
 * `rn-security audit` — every rule, over the whole project.
 *
 * The command a CI job runs. `--fail-on` decides whether the exit code is 1;
 * everything else about the run is reported rather than acted on, because
 * deciding what a finding means is the project's call, not the scanner's.
 */
export async function auditCommand(
  argv: readonly string[],
  context: CliContext,
  toolVersion: string
): Promise<ExitCodeValue> {
  const options = parseScanOptions(argv, context);

  return runScan(
    options,
    {
      rules: builtinRules,
      emptyNote:
        'No findings does not mean no risk: this is static analysis of the code that was read. ' +
        'Check the coverage line above, and pair it with runtime checks on a device.',
    },
    context,
    toolVersion
  );
}
