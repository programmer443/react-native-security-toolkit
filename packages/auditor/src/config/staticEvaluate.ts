import type * as t from '@babel/types';

/**
 * Literal-only evaluation of a configuration expression.
 *
 * `security-toolkit.config.ts` is a TypeScript file in a repository the auditor
 * treats as hostile (§44). Importing it would execute it, and "we ran the
 * project's code to find out whether the project runs unsafe code" is not a
 * defensible position for a security tool — it is the exact supply-chain
 * problem the tool exists to warn about.
 *
 * So the configuration is **parsed and statically evaluated**: literals,
 * objects, arrays, template strings without substitutions, and nothing else.
 * TypeScript authoring is preserved, including `as const`. Anything dynamic —
 * a function call, an environment variable, an import — fails closed with a
 * message naming what was rejected and where.
 */

export class StaticEvaluationError extends Error {
  constructor(
    message: string,
    readonly line?: number
  ) {
    super(message);
    this.name = 'StaticEvaluationError';
  }
}

/** Values a configuration file may produce. */
export type StaticValue =
  | string
  | number
  | boolean
  | null
  | readonly StaticValue[]
  | { readonly [key: string]: StaticValue };

/**
 * Top-level `const` initialisers, so that the common
 * `const config = {...}; export default config;` shape works.
 *
 * One level only, and never across files: resolving arbitrary references would
 * reintroduce, by hand, the evaluation this module exists to avoid.
 */
export type ConstantScope = ReadonlyMap<string, t.Expression>;

function reject(node: t.Node, what: string): never {
  throw new StaticEvaluationError(
    `Configuration must be statically analysable, but ${what} was found. ` +
      `Use literal values only: no function calls, variables, imports or computed keys.`,
    node.loc?.start.line
  );
}

/** Evaluates one expression. Throws {@link StaticEvaluationError} on anything dynamic. */
export function evaluateExpression(
  node: t.Expression,
  scope: ConstantScope = new Map()
): StaticValue {
  switch (node.type) {
    case 'StringLiteral':
      return node.value;
    case 'NumericLiteral':
      return node.value;
    case 'BooleanLiteral':
      return node.value;
    case 'NullLiteral':
      return null;

    case 'TemplateLiteral': {
      if (node.expressions.length > 0) {
        reject(node, 'a template string with substitutions');
      }
      return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('');
    }

    case 'UnaryExpression': {
      const argument = evaluateExpression(node.argument, scope);
      if (node.operator === '-' && typeof argument === 'number') {
        return -argument;
      }
      if (node.operator === '+' && typeof argument === 'number') {
        return argument;
      }
      if (node.operator === '!' && typeof argument === 'boolean') {
        return !argument;
      }
      return reject(node, `the operator "${node.operator}"`);
    }

    case 'ArrayExpression': {
      const values: StaticValue[] = [];
      for (const element of node.elements) {
        if (element === null) {
          reject(node, 'a sparse array');
        }
        if (element.type === 'SpreadElement') {
          const spread = evaluateExpression(element.argument, scope);
          if (!Array.isArray(spread)) {
            reject(element, 'a spread of something that is not an array literal');
          }
          values.push(...spread);
          continue;
        }
        values.push(evaluateExpression(element, scope));
      }
      return values;
    }

    case 'ObjectExpression': {
      const value: Record<string, StaticValue> = {};
      for (const property of node.properties) {
        if (property.type === 'SpreadElement') {
          const spread = evaluateExpression(property.argument, scope);
          if (typeof spread !== 'object' || spread === null || Array.isArray(spread)) {
            reject(property, 'a spread of something that is not an object literal');
          }
          Object.assign(value, spread);
          continue;
        }
        if (property.type === 'ObjectMethod') {
          reject(property, 'a method');
        }
        if (property.computed) {
          reject(property, 'a computed key');
        }

        const key =
          property.key.type === 'Identifier'
            ? property.key.name
            : property.key.type === 'StringLiteral'
              ? property.key.value
              : property.key.type === 'NumericLiteral'
                ? String(property.key.value)
                : reject(property, `a ${property.key.type} key`);

        if (
          property.value.type === 'ArrowFunctionExpression' ||
          property.value.type === 'FunctionExpression'
        ) {
          reject(property.value, 'a function');
        }
        if (
          property.value.type === 'ObjectPattern' ||
          property.value.type === 'ArrayPattern' ||
          property.value.type === 'AssignmentPattern' ||
          property.value.type === 'RestElement' ||
          property.value.type === 'VoidPattern'
        ) {
          reject(property.value, 'a destructuring pattern');
        }

        value[key] = evaluateExpression(property.value, scope);
      }
      return value;
    }

    // `as const`, `satisfies Config` and `<Config>value` are type-level only and
    // carry no runtime behaviour, so they are transparent here.
    case 'TSAsExpression':
    case 'TSSatisfiesExpression':
    case 'TSTypeAssertion':
    case 'TSNonNullExpression':
      return evaluateExpression(node.expression, scope);

    case 'ParenthesizedExpression':
      return evaluateExpression(node.expression, scope);

    case 'Identifier': {
      if (node.name === 'undefined') {
        reject(node, '"undefined"');
      }
      const referenced = scope.get(node.name);
      if (referenced === undefined) {
        reject(node, `the variable "${node.name}"`);
      }
      // A reference is resolved once, from the top-level constants collected
      // before evaluation. Cycles cannot form because the scope is fixed.
      return evaluateExpression(referenced, new Map());
    }

    default:
      return reject(node, `a ${node.type}`);
  }
}

/** Collects top-level `const NAME = <literal>` initialisers for one-level reference resolution. */
export function collectTopLevelConstants(program: t.Program): ConstantScope {
  const constants = new Map<string, t.Expression>();

  for (const statement of program.body) {
    const declaration =
      statement.type === 'VariableDeclaration'
        ? statement
        : statement.type === 'ExportNamedDeclaration' &&
            statement.declaration?.type === 'VariableDeclaration'
          ? statement.declaration
          : undefined;

    if (declaration === undefined || declaration.kind !== 'const') {
      continue;
    }

    for (const declarator of declaration.declarations) {
      if (declarator.id.type === 'Identifier' && declarator.init != null) {
        constants.set(declarator.id.name, declarator.init);
      }
    }
  }

  return constants;
}
