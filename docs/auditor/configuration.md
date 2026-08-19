# Static auditor — configuration

A project configures the auditor with a `security-toolkit.config.*` file in its root. Configuration
is optional: scanning without it is expected to work.

## 1. The file is parsed, never executed

`security-toolkit.config.ts` lives in the repository being scanned, and that repository is treated as
hostile. Importing the file would hand control of the scanning process to the code under analysis, so
the auditor **parses it and statically evaluates the default export** instead.

What that allows:

- object, array, string, number, boolean and `null` literals
- template strings **without** substitutions
- spreads of other literals
- `as const`, `satisfies`, and type annotations — all type-level, all transparent
- one level of top-level `const` reference, so `const config = {…}; export default config;` works

What it refuses, with a message naming what was rejected and on which line:

- function calls — `readFileSync(…)`, `resolve(…)`
- variables from outside the file — `process.env.API_GLOB`
- computed keys, methods, functions as values
- anything else dynamic

Supported filenames, in search order:

```text
security-toolkit.config.ts    .mts    .cts    .js    .mjs    .cjs    .json
```

## 2. Options

```ts
export default {
  // 'minimal' reports high and above · 'standard' low and above · 'strict' everything
  profile: 'standard',

  // Empty or absent means "the whole project, minus exclusions"
  include: ['src/**', 'android/**', 'ios/**'],

  // ADDED TO the built-in exclusions, never replacing them
  exclude: ['**/*.generated.*'],

  rules: {
    disabled: ['RNSEC-SECRET-001'],
    overrides: [{ rule: 'RNSEC-LOG-001', severity: 'low', paths: ['**/test/**'] }],
  },

  // Baseline: findings accepted by fingerprint. A reason is required.
  ignore: [{ fingerprint: 'a1b2c3…', reason: 'sample key in documentation, ticket SEC-14' }],

  severity: {
    failOn: 'high', // reported in the result; the engine never exits a process
    minimum: 'low', // findings below this are counted, not listed
  },

  limits: {
    maxFileBytes: 1_048_576,
    maxParseBytes: 524_288,
    maxFiles: 20_000,
    maxTotalBytes: 134_217_728,
    maxDepth: 24,
    concurrency: 7,
    timeoutMs: 120_000,
  },

  ai: { enabled: false }, // the only accepted value today
};
```

### `exclude` extends the defaults

Built-in exclusions cover `node_modules`, `.git`, build output, `Pods`, `DerivedData`, minified
bundles and source maps. A project's own `exclude` patterns are **added** to them.

Replacing them would be a footgun: adding a single exclusion would silently start scanning
`node_modules`, and the first symptom would be a scan that never finishes.

### Mistakes are errors, not corrections

An unknown option, a misspelled limit, an invalid severity or a malformed baseline entry throws with
an explanatory message. A misspelled key that silently does nothing is how a project comes to believe
a rule is disabled when it is not — and configuration is where a security tool's silence costs most.

### `ai.enabled: true` is refused

AI-assisted analysis is not implemented yet. Accepting the flag and quietly doing nothing would leave
a project believing an analysis ran that never did, so the configuration is rejected with a message
saying so. AI remains opt-in and disabled by default when it does arrive.

## 3. Suppression

Three layers, checked in this order. **Every one of them requires a reason** except a project-wide
rule disable, which is itself an explicit statement in the configuration file.

### Disable a rule everywhere

```ts
rules: {
  disabled: ['RNSEC-SECRET-001'];
}
```

### Accept a specific finding (baseline)

```ts
ignore: [{ fingerprint: '9f2c…', reason: 'documented sample credential' }];
```

Fingerprints come from a previous report and exclude line numbers, so they survive edits elsewhere in
the file. An entry without a reason is a configuration error.

### Suppress one line, in the source

```ts
// security-audit-ignore RNSEC-LOG-001 reason="test fixture"
console.log(token);
```

- Applies to the line the directive is on **and the line after it**, so both conventions work.
- Several rules can be named: `RNSEC-LOG-001, RNSEC-SECRET-001`.
- The comment syntax does not matter — `//`, `#`, `/* */` and `<!-- -->` all work, because the
  scanner looks for the directive text rather than modelling every language's comments.
- **A directive without `reason="…"` does not suppress anything.** It is reported as a suppression
  error instead. Failing open is deliberate: a malformed suppression should show you the finding, not
  swallow it.
- **Put the directive at the line the report names.** When the same problem appears several times in
  one file, the findings merge into one, and the merged finding is reported at the _first_
  occurrence. A directive further down suppresses nothing — the evidence list in the report gives
  every line, so the one to annotate is the first.

## 4. What a report tells you

Beyond the findings themselves:

| Field                          | Why it matters                                                        |
| ------------------------------ | --------------------------------------------------------------------- |
| `truncated`                    | A size, count or depth limit stopped the walk. Coverage is partial.   |
| `timedOut`                     | The wall-clock budget ran out. Coverage is partial.                   |
| `skipped`                      | Every hazard or limit that cost a file, with the reason.              |
| `suppressed`                   | What was hidden, by which layer, and why.                             |
| `suppressionErrors`            | Directives that did not take effect, with their line.                 |
| `ruleErrors`                   | Rules that threw. The scan continues; one broken rule costs one rule. |
| `stats.filesAnalysed`          | Files actually read and examined — a coverage number, not an intent.  |
| `stats.findingsBelowThreshold` | Findings dropped by `severity.minimum`, counted rather than lost.     |
| `exceedsFailOn`                | Whether CI should fail. The engine itself never exits a process.      |
| `aiUsed`                       | Always `false` today, stated in every report rather than assumed.     |
