import type * as t from '@babel/types';

import type { ParsedFile } from '../types/parse.js';

/**
 * A small AST walker.
 *
 * `@babel/traverse` would do this, and would also pull in a scope tracker, a
 * path abstraction and a cache — a large dependency for what rules actually
 * need, which is "visit every node, and know what encloses it". Rules here are
 * shallow pattern matchers over syntax, not type-aware analyses, so the walk is
 * kept small enough to read in one sitting.
 *
 * The ancestor stack is the part that earns its keep: it is what lets a rule say
 * *where* a match was found — the enclosing function or variable — which is what
 * turns a fingerprint into something that survives code moving around a file.
 */

/** A node plus the chain of nodes that contain it, nearest first. */
export interface AstVisit {
  readonly node: t.Node;
  readonly ancestors: readonly t.Node[];
}

const SKIPPED_KEYS = new Set([
  'loc',
  'start',
  'end',
  'range',
  'leadingComments',
  'trailingComments',
  'innerComments',
  'extra',
]);

/** Depth cap. A hostile file can nest expressions far deeper than any human writes. */
const MAX_DEPTH = 400;

/**
 * Visits every node in a parse result.
 *
 * Iterative rather than recursive: the input is attacker-influenced, and a
 * thousand nested parentheses must produce a bounded walk rather than a stack
 * overflow that takes the scan down with it.
 */
export function walk(parsed: ParsedFile | undefined, visit: (entry: AstVisit) => void): void {
  if (parsed === undefined || parsed.kind !== 'javascript') {
    return;
  }

  const stack: Array<{ node: t.Node; ancestors: readonly t.Node[] }> = [
    { node: parsed.ast.program, ancestors: [] },
  ];

  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) {
      break;
    }

    visit(current);

    if (current.ancestors.length >= MAX_DEPTH) {
      continue;
    }

    const childAncestors = [current.node, ...current.ancestors];
    for (const key of Object.keys(current.node)) {
      if (SKIPPED_KEYS.has(key)) {
        continue;
      }
      const value = (current.node as unknown as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        for (const entry of value) {
          if (isNode(entry)) {
            stack.push({ node: entry, ancestors: childAncestors });
          }
        }
      } else if (isNode(value)) {
        stack.push({ node: value, ancestors: childAncestors });
      }
    }
  }
}

function isNode(value: unknown): value is t.Node {
  return typeof value === 'object' && value !== null && typeof (value as t.Node).type === 'string';
}

/** 1-indexed line of a node, or `undefined` when the parser recorded none. */
export function lineOf(node: t.Node): number | undefined {
  return node.loc?.start.line;
}

/** Column of a node, 1-indexed to match editors rather than the parser's 0. */
export function columnOf(node: t.Node): number | undefined {
  const column = node.loc?.start.column;
  return column === undefined ? undefined : column + 1;
}

/**
 * The dotted name of a callee or member expression, e.g. `crypto.createHash`.
 *
 * Returns `undefined` for anything computed or dynamic: `obj[key]()` is not a
 * name, and treating it as one is how a rule ends up matching whatever happens
 * to be in scope.
 */
export function memberName(node: t.Node | null | undefined): string | undefined {
  if (node == null) {
    return undefined;
  }
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'MemberExpression' && !node.computed) {
    const object = memberName(node.object);
    const property = node.property.type === 'Identifier' ? node.property.name : undefined;
    if (object === undefined || property === undefined) {
      return undefined;
    }
    return `${object}.${property}`;
  }
  return undefined;
}

/** The dotted callee name of a call expression, e.g. `console.log`. */
export function calleeName(node: t.Node): string | undefined {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {
    return undefined;
  }
  return memberName(node.callee as t.Node);
}

/** The literal string a node represents, or `undefined` if it is not a static string. */
export function staticString(node: t.Node | null | undefined): string | undefined {
  if (node == null) {
    return undefined;
  }
  if (node.type === 'StringLiteral') {
    return node.value;
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('');
  }
  if (node.type === 'TSAsExpression' || node.type === 'TSSatisfiesExpression') {
    return staticString(node.expression);
  }
  return undefined;
}

/** The property name of an object property, when it is not computed. */
export function propertyName(property: t.Node): string | undefined {
  if (property.type !== 'ObjectProperty') {
    return undefined;
  }
  if (property.computed) {
    return undefined;
  }
  if (property.key.type === 'Identifier') {
    return property.key.name;
  }
  if (property.key.type === 'StringLiteral') {
    return property.key.value;
  }
  return undefined;
}

/**
 * A name for the construct a node sits inside, used as fingerprint context.
 *
 * Prefers the nearest named function, then a variable or property being
 * assigned, then a class. Returns `undefined` at the top level, which is a
 * perfectly good answer.
 */
export function enclosingContext(ancestors: readonly t.Node[]): string | undefined {
  for (const ancestor of ancestors) {
    switch (ancestor.type) {
      case 'FunctionDeclaration':
      case 'FunctionExpression':
        if (ancestor.id?.name !== undefined) {
          return ancestor.id.name;
        }
        break;
      case 'ClassMethod':
      case 'ObjectMethod':
        if (ancestor.key.type === 'Identifier') {
          return ancestor.key.name;
        }
        break;
      case 'VariableDeclarator':
        if (ancestor.id.type === 'Identifier') {
          return ancestor.id.name;
        }
        break;
      case 'ClassDeclaration':
        if (ancestor.id?.name !== undefined) {
          return ancestor.id.name;
        }
        break;
      case 'ObjectProperty': {
        const name = propertyName(ancestor);
        if (name !== undefined) {
          return name;
        }
        break;
      }
      default:
        break;
    }
  }
  return undefined;
}

/** Whether a JSX attribute is present with a literal `true` (or bare) value. */
export function jsxBooleanAttribute(attribute: t.JSXAttribute): boolean | undefined {
  if (attribute.value === null || attribute.value === undefined) {
    // `<WebView javaScriptEnabled />` is `true`.
    return true;
  }
  if (attribute.value.type === 'JSXExpressionContainer') {
    const expression = attribute.value.expression;
    if (expression.type === 'BooleanLiteral') {
      return expression.value;
    }
  }
  return undefined;
}

/** The name of a JSX attribute, ignoring namespaced ones. */
export function jsxAttributeName(attribute: t.Node): string | undefined {
  if (attribute.type !== 'JSXAttribute') {
    return undefined;
  }
  return attribute.name.type === 'JSXIdentifier' ? attribute.name.name : undefined;
}

/** The element name of a JSX opening element, e.g. `WebView`. */
export function jsxElementName(node: t.JSXOpeningElement): string | undefined {
  if (node.name.type === 'JSXIdentifier') {
    return node.name.name;
  }
  if (node.name.type === 'JSXMemberExpression') {
    const object = node.name.object.type === 'JSXIdentifier' ? node.name.object.name : undefined;
    const property = node.name.property.name;
    return object === undefined ? undefined : `${object}.${property}`;
  }
  return undefined;
}
