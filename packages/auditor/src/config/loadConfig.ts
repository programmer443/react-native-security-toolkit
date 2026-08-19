import fs from 'node:fs/promises';
import path from 'node:path';
import { parse } from '@babel/parser';
import type * as t from '@babel/types';

import { AuditorConfigError, resolveConfig } from './resolveConfig.js';
import { collectTopLevelConstants, evaluateExpression } from './staticEvaluate.js';
import type { AuditorConfig } from '../types/config.js';

/**
 * Finding and reading a project's configuration **without executing it**.
 *
 * The obvious implementation — `await import(configPath)` — hands control of the
 * scanning process to the repository being scanned. For a tool whose entire
 * premise is that the target may be malicious (§44), that is not a shortcut, it
 * is the vulnerability. So configuration files are parsed and statically
 * evaluated instead, which keeps TypeScript authoring intact and costs only the
 * ability to compute values at load time.
 *
 * Search order puts TypeScript first because that is the form §42 documents.
 */
const CONFIG_FILENAMES: readonly string[] = [
  'security-toolkit.config.ts',
  'security-toolkit.config.mts',
  'security-toolkit.config.cts',
  'security-toolkit.config.js',
  'security-toolkit.config.mjs',
  'security-toolkit.config.cjs',
  'security-toolkit.config.json',
];

export interface LoadedConfig {
  readonly config: AuditorConfig;
  /** Project-relative path of the file the configuration came from, if any. */
  readonly source?: string;
}

/** Locates a configuration file in a project root. */
export async function findConfigFile(root: string): Promise<string | undefined> {
  for (const filename of CONFIG_FILENAMES) {
    const candidate = path.join(root, filename);
    try {
      const stats = await fs.stat(candidate);
      if (stats.isFile()) {
        return candidate;
      }
    } catch {
      // Absent, which is the normal case for all but one of these names.
    }
  }
  return undefined;
}

/**
 * Loads configuration for a project.
 *
 * A project with no configuration file gets the defaults; that is not an error,
 * and scanning without configuration is expected to work.
 */
export async function loadConfig(root: string, explicitPath?: string): Promise<LoadedConfig> {
  const configPath = explicitPath ?? (await findConfigFile(root));

  if (configPath === undefined) {
    return { config: resolveConfig(undefined) };
  }

  let text: string;
  try {
    text = await fs.readFile(configPath, 'utf8');
  } catch (error: unknown) {
    throw new AuditorConfigError(
      `could not read ${configPath}: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const options = configPath.endsWith('.json')
    ? parseJson(text, configPath)
    : parseModule(text, configPath);

  return {
    config: resolveConfig(options),
    source: path.relative(root, configPath).split(path.sep).join('/'),
  };
}

function parseJson(text: string, configPath: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error: unknown) {
    throw new AuditorConfigError(
      `${configPath} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Extracts the exported configuration object from a JavaScript or TypeScript
 * module, by static analysis only.
 *
 * Both `export default { ... }` and `module.exports = { ... }` are recognised,
 * as is `const config = { ... }; export default config;` — the last because it
 * is how most people actually write a config file, and rejecting it would push
 * them towards a JSON file they cannot comment.
 */
function parseModule(text: string, configPath: string): unknown {
  let file: t.File;
  try {
    file = parse(text, {
      sourceType: 'unambiguous',
      plugins: ['typescript'],
    });
  } catch (error: unknown) {
    throw new AuditorConfigError(
      `${configPath} could not be parsed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const constants = collectTopLevelConstants(file.program);

  for (const statement of file.program.body) {
    if (statement.type === 'ExportDefaultDeclaration') {
      const declaration = statement.declaration;
      if (isExpression(declaration)) {
        return evaluate(declaration, constants, configPath);
      }
      throw new AuditorConfigError(
        `${configPath} exports a ${declaration.type} as its default. Export an object literal.`
      );
    }

    if (
      statement.type === 'ExpressionStatement' &&
      statement.expression.type === 'AssignmentExpression' &&
      isModuleExports(statement.expression.left)
    ) {
      return evaluate(statement.expression.right, constants, configPath);
    }
  }

  throw new AuditorConfigError(
    `${configPath} has no default export. Add "export default { ... }".`
  );
}

function evaluate(
  node: t.Expression,
  constants: ReturnType<typeof collectTopLevelConstants>,
  configPath: string
): unknown {
  try {
    return evaluateExpression(node, constants);
  } catch (error: unknown) {
    const suffix = error instanceof Error ? error.message : String(error);
    throw new AuditorConfigError(`${configPath}: ${suffix}`);
  }
}

function isExpression(node: t.Node): node is t.Expression {
  return (
    node.type !== 'FunctionDeclaration' &&
    node.type !== 'ClassDeclaration' &&
    node.type !== 'TSDeclareFunction' &&
    node.type !== 'TSInterfaceDeclaration' &&
    node.type !== 'TSEnumDeclaration'
  );
}

function isModuleExports(node: t.Node): boolean {
  return (
    node.type === 'MemberExpression' &&
    node.object.type === 'Identifier' &&
    node.object.name === 'module' &&
    node.property.type === 'Identifier' &&
    node.property.name === 'exports'
  );
}
