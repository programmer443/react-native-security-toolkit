/**
 * A deliberately restricted XML element scanner.
 *
 * Used for `AndroidManifest.xml`, `Info.plist` and `*.entitlements`. It is not a
 * general XML parser and does not want to be — for two reasons.
 *
 * **Entity expansion.** A general parser that resolves entities is vulnerable to
 * the billion-laughs attack, and the input here is a file from a repository the
 * auditor assumes is hostile. This scanner never resolves an entity and never
 * reads a DTD, so the attack has nothing to expand into.
 *
 * **Dependency weight.** The alternative is an XML library in a security tool's
 * dependency tree, for the sake of reading a dozen attributes.
 *
 * What it understands: elements, attributes, self-closing tags, comments, CDATA,
 * processing instructions and text content. What it deliberately ignores:
 * namespaces (the prefix is kept as part of the name), DTDs, entities beyond the
 * five predefined ones, and schema validation.
 */

/** One element occurrence, in document order. */
export interface XmlElement {
  /** Tag name as written, including any namespace prefix. */
  readonly name: string;
  readonly attributes: Readonly<Record<string, string>>;
  /** 1-indexed line the element's opening tag starts on. */
  readonly line: number;
  readonly column: number;
  /** Names of the elements containing this one, outermost first. */
  readonly path: readonly string[];
  /** Text directly inside the element, trimmed. Empty for container elements. */
  readonly text: string;
}

/** Bounds: a hostile document must produce a truncated parse, not a hang. */
const MAX_ELEMENTS = 20_000;
const MAX_DEPTH = 200;

const PREDEFINED_ENTITIES: Readonly<Record<string, string>> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

/**
 * Decodes only the five predefined XML entities and numeric character
 * references. A custom entity is left as written rather than resolved, because
 * resolving one means reading a DTD the document controls.
 */
function decodeEntities(value: string): string {
  return value.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, body: string) => {
    if (body.startsWith('#')) {
      const code =
        body.startsWith('#x') || body.startsWith('#X')
          ? Number.parseInt(body.slice(2), 16)
          : Number.parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code >= 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : match;
    }
    return PREDEFINED_ENTITIES[body.toLowerCase()] ?? match;
  });
}

/** Scans a document into a flat list of elements, in document order. */
export function scanXml(source: string): readonly XmlElement[] {
  const elements: XmlElement[] = [];
  // `contentStart` is the offset just after the opening tag, which is where the
  // element's text begins.
  const openStack: Array<{ name: string; index: number; contentStart: number }> = [];
  const lineStarts = computeLineStarts(source);

  let index = 0;
  while (index < source.length && elements.length < MAX_ELEMENTS) {
    const open = source.indexOf('<', index);
    if (open === -1) {
      break;
    }

    // Comments, CDATA and processing instructions carry no elements.
    if (source.startsWith('<!--', open)) {
      const close = source.indexOf('-->', open + 4);
      index = close === -1 ? source.length : close + 3;
      continue;
    }
    if (source.startsWith('<![CDATA[', open)) {
      const close = source.indexOf(']]>', open + 9);
      index = close === -1 ? source.length : close + 3;
      continue;
    }
    if (source.startsWith('<?', open) || source.startsWith('<!', open)) {
      const close = source.indexOf('>', open + 2);
      index = close === -1 ? source.length : close + 1;
      continue;
    }

    const close = findTagEnd(source, open);
    if (close === -1) {
      break;
    }

    const raw = source.slice(open + 1, close);
    index = close + 1;

    if (raw.startsWith('/')) {
      const name = raw.slice(1).trim();
      for (let depth = openStack.length - 1; depth >= 0; depth -= 1) {
        const entry = openStack[depth];
        if (entry?.name === name) {
          const element = elements[entry.index];
          if (element !== undefined) {
            // Text is captured on close, when its extent is known: from the end
            // of the opening tag to the start of this closing tag.
            elements[entry.index] = {
              ...element,
              text: extractText(source, entry.contentStart, open),
            };
          }
          openStack.length = depth;
          break;
        }
      }
      continue;
    }

    const selfClosing = raw.endsWith('/');
    const body = selfClosing ? raw.slice(0, -1) : raw;
    const nameMatch = /^\s*([^\s/>]+)/.exec(body);
    if (nameMatch === null) {
      continue;
    }

    const name = nameMatch[1] ?? '';
    const position = positionOf(lineStarts, open);
    elements.push({
      name,
      attributes: parseAttributes(body.slice(nameMatch[0].length)),
      line: position.line,
      column: position.column,
      path: openStack.map((entry) => entry.name),
      text: '',
    });

    if (!selfClosing && openStack.length < MAX_DEPTH) {
      openStack.push({ name, index: elements.length - 1, contentStart: close + 1 });
    }
  }

  return elements;
}

/**
 * Finds the `>` that ends a tag, respecting quoted attribute values.
 *
 * Naively searching for `>` breaks on `android:value="a > b"`, which is legal
 * and does occur.
 */
function findTagEnd(source: string, open: number): number {
  let quote: string | undefined;
  for (let index = open + 1; index < source.length; index += 1) {
    const character = source[index];
    if (quote !== undefined) {
      if (character === quote) {
        quote = undefined;
      }
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '>') {
      return index;
    }
  }
  return -1;
}

function parseAttributes(body: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  const pattern = /([^\s=/>]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(body)) !== null) {
    const name = match[1];
    const value = match[3] ?? match[4] ?? '';
    if (name !== undefined) {
      attributes[name] = decodeEntities(value);
    }
  }
  return attributes;
}

/** Text between the end of an opening tag and the start of its closing tag. */
function extractText(source: string, contentStart: number, closeTagStart: number): string {
  if (closeTagStart <= contentStart) {
    return '';
  }
  const text = source.slice(contentStart, closeTagStart);
  // A element containing other elements has no direct text worth reporting.
  return text.includes('<') ? '' : decodeEntities(text).trim();
}

function computeLineStarts(source: string): readonly number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === '\n') {
      starts.push(index + 1);
    }
  }
  return starts;
}

function positionOf(
  lineStarts: readonly number[],
  offset: number
): { line: number; column: number } {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if ((lineStarts[middle] ?? 0) <= offset) {
      low = middle;
    } else {
      high = middle - 1;
    }
  }
  return { line: low + 1, column: offset - (lineStarts[low] ?? 0) + 1 };
}

/** Finds every element with a given tag name. */
export function elementsNamed(
  elements: readonly XmlElement[],
  name: string
): readonly XmlElement[] {
  return elements.filter((element) => element.name === name);
}

/**
 * Reads an Apple property list into key/value pairs.
 *
 * Property lists are XML with a positional convention — `<key>` followed by its
 * value element — rather than a nesting one, so the flat element list is
 * actually the convenient shape here. Nested dictionaries are exposed with
 * dotted key paths, e.g. `NSAppTransportSecurity.NSAllowsArbitraryLoads`.
 */
export interface PlistEntry {
  readonly keyPath: string;
  /** `true`, `false`, a string, or the element name for structures. */
  readonly value: string;
  readonly type:
    'true' | 'false' | 'string' | 'integer' | 'real' | 'data' | 'date' | 'array' | 'dict';
  readonly line: number;
}

export function scanPlist(source: string): readonly PlistEntry[] {
  const elements = scanXml(source);
  const entries: PlistEntry[] = [];
  const dictKeyStack: string[] = [];

  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    if (element === undefined || element.name !== 'key') {
      continue;
    }

    // Depth within the plist tells us which enclosing dictionary a key belongs
    // to; `path` records the elements above it.
    const depth = element.path.filter((name) => name === 'dict').length;
    dictKeyStack.length = Math.max(0, depth - 1);

    const value = elements[index + 1];
    if (value === undefined) {
      continue;
    }

    const keyPath = [...dictKeyStack, element.text].filter((part) => part !== '').join('.');

    if (value.name === 'dict' || value.name === 'array') {
      dictKeyStack[Math.max(0, depth - 1)] = element.text;
      entries.push({ keyPath, value: value.name, type: value.name, line: element.line });
      continue;
    }

    const type = normaliseType(value.name);
    if (type === undefined) {
      continue;
    }
    entries.push({
      keyPath,
      value: type === 'true' || type === 'false' ? type : value.text,
      type,
      line: element.line,
    });
  }

  return entries;
}

function normaliseType(name: string): PlistEntry['type'] | undefined {
  switch (name) {
    case 'true':
    case 'false':
    case 'string':
    case 'integer':
    case 'real':
    case 'data':
    case 'date':
      return name;
    default:
      return undefined;
  }
}
