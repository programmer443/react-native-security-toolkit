/**
 * Everything the CLI touches outside itself, in one injectable object.
 *
 * `process.stdout`, `process.cwd()` and the exit code are the three things that
 * make command-line tools awkward to test, so none of the commands reach for
 * them directly. A test supplies writers that collect strings, and asserts on
 * what the command *would* have printed and returned.
 */
export interface CliContext {
  readonly cwd: string;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  /** Whether a person is watching. Drives colour, and nothing else. */
  readonly isTty: boolean;
}

/**
 * Exit codes, fixed so a CI script can branch on them.
 *
 * The distinction that matters is between **2 and 1**: a configuration mistake
 * and a security finding are different events, and a pipeline that cannot tell
 * them apart will eventually treat a broken config as a clean scan.
 */
export const ExitCode = {
  /** Nothing met the failure threshold. */
  Ok: 0,
  /** At least one finding met `--fail-on`. */
  FindingsAtOrAboveThreshold: 1,
  /** Bad usage, bad configuration, or an unreadable target. */
  UsageError: 2,
  /** The CLI itself failed. A bug, not a verdict about the project. */
  InternalError: 3,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

/** An error the user can act on. Reported as a message, never as a stack trace. */
export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: ExitCodeValue = ExitCode.UsageError
  ) {
    super(message);
    this.name = 'CliError';
  }
}
