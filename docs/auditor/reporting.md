# Reporting

One scan, five renderings. A format is never a reason to re-run an audit — a CI job that publishes
SARIF _and_ prints a console summary is describing the same run, which is what makes the two
consistent.

| Format     | Extension | For                                              |
| ---------- | --------- | ------------------------------------------------ |
| `console`  | `.txt`    | A person reading a terminal                      |
| `json`     | `.json`   | Dashboards, scripts, anything that is not GitHub |
| `markdown` | `.md`     | A pull request comment or a CI job summary       |
| `html`     | `.html`   | A self-contained artefact to open in a browser   |
| `sarif`    | `.sarif`  | GitHub code scanning, and other SARIF consumers  |

```ts
import { auditProject, builtinRules, getReporter } from '@rn-security/auditor';

const report = await auditProject({ root, rules: [...builtinRules] });
process.stdout.write(getReporter('sarif').render(report, { toolVersion: '0.1.0' }));
```

Reporters are pure functions of the report. They write nothing and fetch nothing — writing bytes
somewhere is the caller's job, which is also what makes output formats testable at all.

## Three properties every format shares

**Coverage is stated, not implied.** A scan that hit a limit says so in every format. "No findings"
from a run that stopped after 200 of 20,000 files means something quite different, and a reader has
no way to tell unless the report tells them.

**The local root stays out.** Reports travel — into CI logs, pull requests, issue trackers.
`/Users/someone/work/client-project` is noise at best, and occasionally something the author would
rather not publish. Pass `includeRoot: true` when it genuinely helps.

**Untrusted content is escaped.** Titles, paths and snippets all originate in the repository under
analysis. A repository can contain a file literally named
`src/<img src=x onerror=alert(1)>.ts` — so the HTML reporter escapes every interpolation, the
Markdown reporter escapes table and emphasis characters, and the SARIF reporter percent-encodes
paths. That last one is not theoretical: an unencoded angle bracket produces a SARIF file that fails
schema validation, and a rejected upload is silent from the developer's side.

## SARIF

Validated in CI against **the specification's own schema**
([`sarif-2.1.0.schema.json`](../../packages/auditor/src/reporting/__tests__/fixtures/sarif-2.1.0.schema.json),
committed unmodified), rather than against our reading of it. Hand-written assertions pass happily
while producing a file GitHub rejects.

What the reporter takes care of:

- **`level` is not severity.** SARIF has three useful levels; the audit has five severities. The
  mapping is in one place, and the finer detail rides on `security-severity`.
- **`security-severity` is a string holding a number**, which is how GitHub buckets alerts. Omit it
  and every alert shows as a warning whatever the report said. The values are band midpoints, not a
  CVSS calculation — the auditor does not compute a vector, and pretending otherwise would be
  fabricated precision.
- **`partialFingerprints`** carry the auditor's line-number-free fingerprint, which is what lets an
  alert survive an edit above the finding.
- **Suppressed findings are still results**, carrying a `suppressions` entry with the recorded
  reason. GitHub shows them as dismissed. Dropping them silently would hide a decision someone made.
- **An incomplete scan becomes a tool notification**, and a rule that threw marks the invocation
  unsuccessful.
- **Paths are relative to `%SRCROOT%`** and percent-encoded.

### In CI

```yaml
- name: Generate SARIF
  if: always()
  run: rn-security audit . --format sarif --min info --out rn-security.sarif

- name: Upload SARIF to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@f3712979fa5f215279b101dd0a2e3bdfb4353324 # v3
  with:
    sarif_file: rn-security.sarif
    category: rn-security-auditor
```

`--min info` because GitHub does its own filtering, and a finding missing from the SARIF is a finding
nobody sees. The job needs `permissions: security-events: write`.

> **Not yet verified end to end.** The SARIF validates against the specification schema, and the
> upload step is wired as above — but this repository has not yet pushed to GitHub, so ingestion by
> code scanning has not been observed in a live run. That is the one part of the Phase 8 exit
> criteria still outstanding, and it is stated here rather than assumed.

## Console

Severity-ordered, one block per finding, with the reasoning attached: evidence, standards, the
remediation, and the fingerprint to suppress it with. Colour is off unless the caller asks — piping
a report into a file and finding it full of escape codes is a small thing that makes a tool feel
careless.

## JSON

A versioned envelope. `schemaVersion` is **not** the package version: a consumer needs to know
whether the shape changed, and tying that to a release number makes every patch look breaking.
Summary counts are precomputed so a dashboard does not have to re-derive them.

## Markdown

Grouped by severity under a summary table, with a `> [!WARNING]` block when coverage was incomplete.
Suitable for posting as a pull request comment.

## HTML

A single file: inline styles, **no script anywhere**, no external resource. It opens from a `file://`
URL with no network access, which is how a CI artefact is usually read. A report that executes a
`<script>` planted in a filename would hand an attacker the reviewer's browser, so there is nothing
executable in the output at all.

## What is not here

- **Diffing against a previous run.** Fingerprints make it possible, and the baseline file already
  uses them, but nothing computes "new since last scan" yet.
- **Per-format configuration** — grouping, sorting, verbosity. The formats are deliberately opinionated
  until there is a reason not to be.
