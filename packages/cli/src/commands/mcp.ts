import path from 'node:path';

import { CliError, ExitCode } from '../context.js';
import { parseSafely } from '../options.js';
import type { CliContext, ExitCodeValue } from '../context.js';

/**
 * `rn-security mcp` — serve the findings to whichever AI model the developer
 * already uses.
 *
 * This is the toolkit's answer to "AI-assisted security review", and the shape
 * of it is deliberate. The toolkit takes no API key, picks no vendor, and
 * uploads nothing: it speaks the Model Context Protocol over stdio, so the model
 * is the one the developer has already chosen and already trusts, and the source
 * never leaves the machine on this tool's initiative.
 *
 * The server lives in `@rn-security/mcp`, which is an optional install — the CLI
 * does not depend on it, so a project that only wants audits never pays for it.
 */
export async function mcpCommand(
  argv: readonly string[],
  context: CliContext,
  toolVersion: string
): Promise<ExitCodeValue> {
  const { values, positionals } = parseSafely(argv, { root: { type: 'string' } });

  const root = path.resolve(
    context.cwd,
    (values['root'] as string | undefined) ?? positionals[0] ?? '.'
  );

  let server: { runStdioServer: (options: { root: string; version: string }) => Promise<void> };
  try {
    server = (await import('@rn-security/mcp')) as typeof server;
  } catch {
    throw new CliError(
      [
        'The MCP server is a separate, optional package. Install it:',
        '',
        '  npm install --save-dev @rn-security/mcp',
        '',
        'Then register it with your AI client, for example:',
        '',
        '  claude mcp add rn-security -- npx -y @rn-security/mcp',
        '',
        'It is read-only, confined to the directory it starts in, and sends nothing anywhere.',
      ].join('\n')
    );
  }

  // stdout now belongs to the protocol: a stray line there corrupts the stream
  // and surfaces as a client error that looks nothing like its cause.
  await server.runStdioServer({ root, version: toolVersion });
  return ExitCode.Ok;
}
