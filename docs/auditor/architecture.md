# Static auditor — core engine

`@rn-security/auditor` · package `packages/auditor`

> The auditor runs on a developer machine or in CI. **It is never part of a mobile application
> bundle.** That is why it is a separate package: an app that only wants `RootDetection.getStatus()`
> should not install a JavaScript parser.

## 1. What exists today

The engine (Phase 5), the rule library (Phase 6) and the standards knowledge layer (Phase 7).

- **Engine** — discovery, classification, parsing, the rule contract, fingerprints, deduplication,
  suppression, severity resolution and configuration loading.
- **Rules** — fourteen rules covering secrets, storage, cryptography, network and TLS, WebViews,
  deep links, logging, Android manifest configuration, iOS App Transport Security, dependencies and
  dynamic code execution. Each is documented in [docs/rules](../rules/README.md) and tested against
  four cases: true positive, true negative, edge case, and the false positive it would most
  plausibly produce.
- **Knowledge** — CWE, MASWE, MASVS and MASTG identifiers, generated from the official sources and
  validated at rule registration. See [knowledge.md](knowledge.md).

Still to come: reporting formats and the CLI (Phases 8–9), and optional AI analysis (Phase 10).

The engine runs whatever rules it is given — the built-in set by default, which is also how it is
tested:

```ts
import { auditProject, builtinRules, loadConfig } from '@rn-security/auditor';

const { config } = await loadConfig(projectRoot);
const report = await auditProject({ root: projectRoot, config, rules: [...builtinRules] });
```

Or against this repository, which is how the toolkit audits itself (§58):

```sh
pnpm security:audit
```

## 2. The pipeline

```text
Target repository (treated as HOSTILE)
        │
        ▼
  Discovery        no symlink following · size, count and depth caps · binary sniffing
        │          path-traversal guard · directory pruning · every skip recorded
        ▼
  Classification   language and role from the path alone, before anything is read
        │
        ▼
  Read + parse     one parse per file, shared by every rule · bounded concurrency
        │          byte cap before the parser sees anything
        ▼
  Rules            selected by language and file kind · pure functions of their context
        │
        ▼
  Findings         fingerprint (line-number-free)
        │
        ├──▶ Deduplication      same fingerprint, merged: strongest claim, union of evidence
        ├──▶ Suppression        disabled rules · baseline · inline directives
        ├──▶ Severity           rule default, adjusted for context, adjustment recorded
        └──▶ Threshold          findings below the reporting floor counted, not hidden
                    │
                    ▼
              AuditReport
```

## 3. The repository is hostile

Every defence below exists because a repository can contain the thing it defends against — whether
by malice or by an unlucky `find`. All of them are covered by
[`src/__tests__/hostileRepository.test.ts`](../../packages/auditor/src/__tests__/hostileRepository.test.ts),
whose assertions are mostly about what the auditor **did not** do.

| Hazard                                         | What the auditor does                                      |
| ---------------------------------------------- | ---------------------------------------------------------- |
| Symbolic link to `~/.ssh`, `/etc`, `/`         | Never follows a link. Records it as skipped.               |
| Symbolic link loop                             | Same: links are not traversed, so a loop cannot form.      |
| Enormous file                                  | Skipped above `maxFileBytes`, with its size in the record. |
| Project larger than the budget                 | Stops at `maxTotalBytes`, sets `truncated`.                |
| Pathological directory nesting                 | Iterative walk with a depth cap; no recursion to overflow. |
| Binary file named `helpers.ts`                 | Content sniffed at read time and skipped.                  |
| `package.json` with install scripts            | Nothing is ever installed or executed.                     |
| `security-toolkit.config.ts` with side effects | Parsed and statically evaluated, never imported.           |
| Prompt injection in source                     | Source is data. No AI runs in this phase; reports say so.  |
| Unicode and awkward path names                 | Handled; paths are normalised to project-relative POSIX.   |

**Nothing from the target project is ever executed.** No `import`, no `require`, no `eval`, no
`npm install`, no package script, no spawned process. For a tool whose premise is that the target may
be malicious, running its code to find out whether it runs unsafe code is not a shortcut — it is the
vulnerability.

## 4. Two things a scanner must never do quietly

**Report a partial scan as a complete one.** Every limit, skip, unreadable path, rule failure and
malformed suppression appears in the report. `truncated` and `timedOut` are part of the contract, not
diagnostics: "no findings" from a scan that stopped after 200 of 20,000 files means nothing, and the
consumer has to be able to tell the difference.

**Hide a finding without a reason.** Suppression requires a reason at every layer, and a directive
that fails to give one is reported as a suppression error and does not take effect. Failing open is
deliberate — a malformed suppression should show you the finding.

## 5. Fingerprints

```text
sha256( ruleId ‖ projectRelativePath ‖ structuralContext ‖ normalisedEvidence )
```

**Line numbers are deliberately excluded.** A fingerprint that moves when an import is added at the
top of a file invalidates every suppression below it, and a baseline that has to be regenerated after
every edit is a baseline nobody keeps.

The trade is real and accepted: two identical problems in the same structural context of the same
file collapse into one finding. Rules that care can separate them by supplying a `structuralContext`
— an enclosing function name, a configuration key path.

Evidence is whitespace-normalised but **case-preserving**: lowercasing would merge two credentials
that differ only in case, which is exactly the pair a secrets rule must keep apart. Fields are joined
with a NUL separator so that moving text between fields cannot produce the same digest.

## 6. Severity is computed, not declared

A rule declares a base severity. The engine adjusts it for context and **records the adjustment on
the finding**:

| Context                            | Adjustment                    |
| ---------------------------------- | ----------------------------- |
| Fixture, mock or snapshot          | Down 2 levels                 |
| Test code                          | Down 1 level                  |
| Example or demo application        | Down 1 level                  |
| `rules.overrides` in configuration | Applied as written, and final |

Nothing is ever dropped outright: a real credential committed to a fixture directory is still a real
credential, so the floor is `info`, not silence. A configuration override outranks the engine's
judgement, because second-guessing an explicit decision would make overrides untrustworthy.

## 7. Bounded everything

| Limit           | Default | What it bounds                                 |
| --------------- | ------- | ---------------------------------------------- |
| `maxFileBytes`  | 1 MiB   | Largest file read                              |
| `maxParseBytes` | 512 KiB | Largest file parsed (rules still see the text) |
| `maxFiles`      | 20,000  | Files offered to rules                         |
| `maxTotalBytes` | 128 MiB | Total bytes read from the project              |
| `maxDepth`      | 24      | Directory nesting                              |
| `concurrency`   | cores−1 | Files analysed at once                         |
| `timeoutMs`     | 120,000 | Wall-clock budget for a whole scan             |

`Promise.all(allFiles.map(scan))` is forbidden: on a large repository it opens every file at once and
holds every file's text in memory simultaneously. A bounded scheduler keeps a fixed number of tasks
in flight, and one core is left free — an auditor that makes a laptop unusable gets switched off,
which is a security outcome as surely as a missed finding is.

## 8. Known limitations

Stated here rather than discovered later:

- **A single hostile file can stall a scan.** Parsing is synchronous and cannot be interrupted, so a
  file crafted to make the parser take quadratic time is bounded only by `maxParseBytes`. Worker
  isolation — which would allow a genuine per-file timeout — is deferred until there is a second
  parser to justify the complexity. The wall-clock budget stops the scan _between_ files, not
  inside one.
- **Only JavaScript, TypeScript, JSX and TSX are parsed.** Kotlin, Java, Swift, Objective-C, XML,
  plists and Gradle files are discovered and classified, and rules receive their text, but there is
  no AST for them yet. Language parsers arrive with the rules that need them.
- **Plugin selection for `.js` is a guess.** React Native projects mix plain JavaScript, JSX and
  Flow. The parser tries the plausible combinations in order rather than picking one and mislabelling
  the file.
- **Glob support is a deliberate subset**: `**`, `*`, `?` and `{a,b}`. Anything else in a pattern is
  a literal. The matcher is small on purpose — it consumes attacker-influenced path names before any
  size limit applies, and glob libraries have a long history of catastrophic backtracking.
- **Fingerprints collapse identical findings in the same structural context.** See §5.
- **Rules see one file at a time.** There is no cross-file data flow, so a credential passed through
  three functions before reaching storage is invisible. Every rule's page states what this costs it.
- **A directive-shaped string is read as a directive.** The suppression scanner looks for the token
  after a comment opener; a string literal containing `// security-audit-ignore …` still matches.
  This package's own test data trips it when the auditor scans itself, which is the honest
  demonstration of the limit.

## 9. Where to look

| Concern                     | File                                                      |
| --------------------------- | --------------------------------------------------------- |
| Hostile-safe walk           | `src/discovery/discoverFiles.ts`                          |
| Language and role of a file | `src/classification/classify.ts`                          |
| Parsing and the parse cache | `src/parsers/javascript.ts`                               |
| Orchestration               | `src/engine/auditProject.ts`                              |
| Finding identity            | `src/engine/fingerprint.ts`                               |
| Merging duplicates          | `src/engine/dedupe.ts`                                    |
| Suppression                 | `src/engine/suppression.ts`                               |
| Contextual severity         | `src/engine/severity.ts`                                  |
| Configuration               | `src/config/loadConfig.ts`, `src/config/resolveConfig.ts` |

Rules live in `src/rules/<category>/`, with shared analysis helpers in `src/analysis/` (AST walking,
sensitivity heuristics, entropy, XML and property-list scanning).

Configuration is documented separately in [configuration.md](configuration.md), the standards layer
in [knowledge.md](knowledge.md), and each rule in [docs/rules](../rules/README.md).
