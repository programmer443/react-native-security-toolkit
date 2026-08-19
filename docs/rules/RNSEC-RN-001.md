# RNSEC-RN-001 — Dynamic code execution

|                   |                                                     |
| ----------------- | --------------------------------------------------- |
| **Base severity** | critical (`eval`, `Function`), high (string timers) |
| **Confidence**    | very-high / high                                    |
| **Categories**    | react-native, serialization                         |
| **Applies to**    | JavaScript, JSX, TypeScript, TSX                    |

## What it detects

`eval(...)`, `global.eval(...)`, `Function(...)`, `new Function(...)`, and `setTimeout` /
`setInterval` given code as a string.

## Why it matters

Each of these turns a value into executable code. In a React Native application the value is
frequently something the application received — a deep link parameter, a response body, a WebView
message — and the code runs with the application's full JavaScript privileges: the session, the local
database, and anything the native bridge exposes.

## Vulnerable

```ts
export function runPlugin(source: string): unknown {
  return eval(source);
}

setTimeout('refresh()', 1000);
```

## Secure

```ts
export function runPlugin(name: string, plugins: Record<string, () => unknown>): unknown {
  return plugins[name]?.();
}

setTimeout(() => refresh(), 1000);
```

Parse data with `JSON.parse`, dispatch behaviour through a lookup table keyed by a validated value,
and pass functions rather than strings to timers. Never execute JavaScript fetched at runtime: it
bypasses store review and turns any compromise of the hosting server into code execution inside the
application.

## Standards

| Standard           | Identifiers                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| CWE                | CWE-95, CWE-94                                                                                                                  |
| MASWE              | MASWE-0049                                                                                                                      |
| MASVS              | MASVS-CODE-4                                                                                                                    |
| MASTG verification | MASTG has no test mapped to MASWE-0049 in the shipped snapshot. Verify by reviewing every dynamic-execution site and its input. |

## False positives it deliberately avoids

- A method that merely happens to be named `evaluate`.
- A property access such as `interpreter.eval` that is not a call.
- Timers given a function, which is the correct form.

## Limitations

- Whether the executed value is attacker-influenced is not determined. A constant passed to `eval` is
  still reported, because the construct itself is what needs removing.
- Runtime bundle loading — fetching JavaScript and handing it to the engine through a native module —
  is not detected, since it has no single recognisable shape.
- Only the JavaScript family is covered. Dynamic loading of native code (`DexClassLoader`,
  `dlopen`) is a separate weakness and is not yet a rule.

## Suppression

```ts
// security-audit-ignore RNSEC-RN-001 reason="expression evaluator over a constant grammar, no external input"
```

## Tests

`packages/auditor/src/rules/__tests__/dependenciesAndDynamicCode.test.ts`
