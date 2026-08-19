import { auditCommand } from './commands/audit.js';
import { dependenciesCommand } from './commands/dependencies.js';
import { mcpCommand } from './commands/mcp.js';
import { reportCommand } from './commands/report.js';
import { rulesCommand } from './commands/rules.js';
import { runtimeCommand } from './commands/runtime.js';
import { secretsCommand } from './commands/secrets.js';
import { CliError, ExitCode } from './context.js';
import type { CliContext, ExitCodeValue } from './context.js';

/**
 * `rn-security` — the command line over the static auditor.
 *
 * Two rules shape the whole CLI:
 *
 * **It reports; it does not act.** Nothing here edits a file, installs anything,
 * or changes a project's security configuration (§72). The strongest thing it
 * does is set an exit code, and even that is opt-in through `--fail-on`.
 *
 * **It never claims a capability it does not have.** `runtime` inspects project
 * configuration and says plainly that it cannot check a device; `dependencies`
 * says plainly that it is not a vulnerability scanner.
 */

/**
 * Fallback only. The bin shim reads the real version from `package.json` and
 * passes it in — a constant here would drift at the first release, and it ends
 * up in every JSON and SARIF report this CLI writes.
 */
export const VERSION = '0.0.0-unknown';

const USAGE = `rn-security — static security analysis for React Native projects

Usage
  rn-security <command> [path] [options]

Commands
  audit [path]              Run every rule over the project
  secrets [path]            Credential detection only
  dependencies [path]       Dependency resolution checks (not a vulnerability scanner)
  runtime [path]            Project readiness for the runtime checks — does not touch a device
  report <file.json>        Re-render a JSON report in another format
  rules                     List the rules this build ships
  mcp [path]                Serve findings to your AI model over the Model Context Protocol

Scan options
  --format <name>           console | json | markdown | html | sarif   (default: console)
  -o, --out <file>          Write to a file instead of stdout
  --fail-on <severity>      Exit 1 when a finding is this severe or worse
  --min <severity>          Drop findings below this severity from the report
  -c, --config <file>       Configuration file, overriding discovery
  --include-root            Include the absolute project root in the output
  --color / --no-color      Force colour on or off

Other
  -h, --help                Show this help
  -v, --version             Show the version

Exit codes
  0  nothing met the failure threshold
  1  a finding met --fail-on
  2  usage, configuration or target error
  3  the CLI itself failed

Severities: critical, high, medium, low, info
Docs: docs/auditor/  ·  Rules: docs/rules/
`;

export interface RunOptions {
  /** Version reported by --version and recorded in machine-readable output. */
  readonly version?: string;
}

/**
 * Runs one command and returns its exit code.
 *
 * Never throws and never touches `process`: the bin shim owns the process, and
 * this function owns the decision. That separation is what lets every command be
 * tested in-process, and it is why an unexpected failure becomes exit code 3
 * with a message rather than a stack trace on a developer's terminal.
 */
export async function run(
  argv: readonly string[],
  context: CliContext,
  options: RunOptions = {}
): Promise<ExitCodeValue> {
  const version = options.version ?? VERSION;

  try {
    const [command, ...rest] = argv;

    if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
      context.stdout(USAGE);
      return ExitCode.Ok;
    }

    if (command === '--version' || command === '-v') {
      context.stdout(`${version}\n`);
      return ExitCode.Ok;
    }

    switch (command) {
      case 'audit':
        return await auditCommand(rest, context, version);
      case 'secrets':
        return await secretsCommand(rest, context, version);
      case 'dependencies':
        return await dependenciesCommand(rest, context, version);
      case 'runtime':
        return await runtimeCommand(rest, context);
      case 'report':
        return await reportCommand(rest, context, version);
      case 'rules':
        return await rulesCommand(rest, context);
      case 'mcp':
        return await mcpCommand(rest, context, version);
      default:
        context.stderr(`Unknown command "${command}".\n\n${USAGE}`);
        return ExitCode.UsageError;
    }
  } catch (error: unknown) {
    if (error instanceof CliError) {
      // Something the user can fix: say what, and nothing else.
      context.stderr(`${error.message}\n`);
      return error.exitCode;
    }

    // A bug in the tool. The stack is genuinely useful here, and the exit code
    // distinguishes it from a security finding.
    context.stderr(
      `rn-security failed unexpectedly. This is a bug in the tool, not a finding about your project.\n` +
        `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`
    );
    return ExitCode.InternalError;
  }
}

export { ExitCode } from './context.js';
export type { CliContext, ExitCodeValue } from './context.js';
