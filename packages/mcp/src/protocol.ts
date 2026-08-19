/**
 * The Model Context Protocol, over stdio, implemented directly.
 *
 * The official SDK would do this too, and it pulls in seventeen transitive
 * dependencies — express, hono, jose, ajv, zod — for HTTP transports and OAuth
 * this server does not use. In a tool whose entire premise is that dependencies
 * are a supply-chain decision, seventeen packages to frame JSON-RPC on stdin is
 * not a trade worth making. What is implemented here is small enough to read in
 * one sitting, and the protocol version it speaks is pinned and stated.
 *
 * Implements MCP `2025-06-18`: `initialize`, `notifications/initialized`,
 * `ping`, `tools/list`, `tools/call`. Everything else answers with
 * `-32601 Method not found`, which is what a well-behaved server does for
 * capabilities it never advertised.
 */

export const PROTOCOL_VERSION = '2025-06-18';

/** JSON-RPC error codes used here, from the JSON-RPC 2.0 specification. */
export const JsonRpcError = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
} as const;

export interface JsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  readonly jsonrpc: '2.0';
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: { code: number; message: string; data?: unknown };
}

/** One tool, as advertised in `tools/list`. */
export interface McpTool {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema?: Record<string, unknown>;
  /**
   * Behaviour hints for the client.
   *
   * Every tool this server exposes is read-only and closed-world, and says so.
   * A client is entitled to distrust annotations from an unknown server — these
   * are declarations of intent, and the code behind them is what actually
   * enforces it.
   */
  readonly annotations?: {
    readonly readOnlyHint?: boolean;
    readonly destructiveHint?: boolean;
    readonly idempotentHint?: boolean;
    readonly openWorldHint?: boolean;
  };
  handler(args: Record<string, unknown>): Promise<ToolOutcome>;
}

export interface ToolOutcome {
  /** Structured result. Serialised into a text block as well, per the specification. */
  readonly structured: Record<string, unknown>;
  /** Set when the tool failed in a way the model should see and can react to. */
  readonly isError?: boolean;
  /** Human-readable summary placed before the JSON, so a model does not have to parse to orient. */
  readonly summary?: string;
}

export interface ServerInfo {
  readonly name: string;
  readonly title: string;
  readonly version: string;
  /**
   * Sent to the client at initialize.
   *
   * This is where the server tells the model how to treat what it is about to
   * receive: findings quote a repository the server does not trust, and text
   * inside them is data, never instruction.
   */
  readonly instructions: string;
}

/** Builds a response for one incoming message, or `undefined` for a notification. */
export async function handleMessage(
  message: unknown,
  tools: readonly McpTool[],
  info: ServerInfo
): Promise<JsonRpcResponse | undefined> {
  if (typeof message !== 'object' || message === null || Array.isArray(message)) {
    return errorResponse(null, JsonRpcError.InvalidRequest, 'Expected a JSON-RPC object.');
  }

  const request = message as JsonRpcRequest;
  if (request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
    return errorResponse(
      request.id ?? null,
      JsonRpcError.InvalidRequest,
      'Not a JSON-RPC 2.0 request.'
    );
  }

  // A notification has no id and takes no response, however it turns out.
  const isNotification = request.id === undefined;

  switch (request.method) {
    case 'initialize': {
      if (isNotification) {
        return undefined;
      }
      return {
        jsonrpc: '2.0',
        id: request.id ?? null,
        result: {
          // The specification says to answer with the client's version when it
          // is supported, and with ours otherwise. Ours is the only one we
          // speak, so it is always ours.
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: info.name, title: info.title, version: info.version },
          instructions: info.instructions,
        },
      };
    }

    case 'notifications/initialized':
    case 'notifications/cancelled':
      return undefined;

    case 'ping':
      return isNotification ? undefined : { jsonrpc: '2.0', id: request.id ?? null, result: {} };

    case 'tools/list': {
      if (isNotification) {
        return undefined;
      }
      return {
        jsonrpc: '2.0',
        id: request.id ?? null,
        result: {
          tools: tools.map((tool) => ({
            name: tool.name,
            title: tool.title,
            description: tool.description,
            inputSchema: tool.inputSchema,
            ...(tool.outputSchema === undefined ? {} : { outputSchema: tool.outputSchema }),
            ...(tool.annotations === undefined ? {} : { annotations: tool.annotations }),
          })),
        },
      };
    }

    case 'tools/call': {
      if (isNotification) {
        return undefined;
      }
      const name = request.params?.['name'];
      const args = request.params?.['arguments'];

      if (typeof name !== 'string') {
        return errorResponse(request.id ?? null, JsonRpcError.InvalidParams, 'Missing tool name.');
      }
      const tool = tools.find((candidate) => candidate.name === name);
      if (tool === undefined) {
        return errorResponse(
          request.id ?? null,
          JsonRpcError.MethodNotFound,
          `Unknown tool: ${name}`
        );
      }
      if (
        args !== undefined &&
        (typeof args !== 'object' || args === null || Array.isArray(args))
      ) {
        return errorResponse(
          request.id ?? null,
          JsonRpcError.InvalidParams,
          'Arguments must be an object.'
        );
      }

      try {
        const outcome = await tool.handler((args as Record<string, unknown> | undefined) ?? {});
        return {
          jsonrpc: '2.0',
          id: request.id ?? null,
          result: {
            // Structured *and* serialised: the specification asks for the JSON
            // in a text block too, for clients that do not read
            // `structuredContent`.
            content: [
              {
                type: 'text',
                text:
                  outcome.summary === undefined
                    ? JSON.stringify(outcome.structured, null, 2)
                    : `${outcome.summary}\n\n${JSON.stringify(outcome.structured, null, 2)}`,
              },
            ],
            structuredContent: outcome.structured,
            isError: outcome.isError === true,
          },
        };
      } catch (error: unknown) {
        // A tool that throws is reported as a tool error, not a protocol error:
        // the model can read it and try something else, which is the point of
        // the distinction in the specification.
        return {
          jsonrpc: '2.0',
          id: request.id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text: `${name} failed: ${error instanceof Error ? error.message : String(error)}`,
              },
            ],
            isError: true,
          },
        };
      }
    }

    default:
      return isNotification
        ? undefined
        : errorResponse(
            request.id ?? null,
            JsonRpcError.MethodNotFound,
            `This server implements initialize, ping, tools/list and tools/call. Received "${request.method}".`
          );
  }
}

function errorResponse(id: string | number | null, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/**
 * Reads newline-delimited JSON-RPC from a stream and writes responses to another.
 *
 * stdout carries protocol only. Anything the server wants to say to a human goes
 * to stderr — a stray `console.log` in an MCP server corrupts the stream and
 * produces a client error that looks nothing like its cause.
 */
export function createStdioLoop(options: {
  readonly tools: readonly McpTool[];
  readonly info: ServerInfo;
  readonly write: (line: string) => void;
}): (chunk: string) => Promise<void> {
  let buffer = '';

  return async function consume(chunk: string): Promise<void> {
    buffer += chunk;

    for (;;) {
      const newline = buffer.indexOf('\n');
      if (newline === -1) {
        return;
      }
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);

      if (line === '') {
        continue;
      }

      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        options.write(
          `${JSON.stringify(errorResponse(null, JsonRpcError.ParseError, 'Invalid JSON.'))}\n`
        );
        continue;
      }

      const response = await handleMessage(message, options.tools, options.info);
      if (response !== undefined) {
        options.write(`${JSON.stringify(response)}\n`);
      }
    }
  };
}
