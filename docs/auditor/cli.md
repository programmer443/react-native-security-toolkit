# `rn-security` — the command line

```sh
npx rn-security audit .
npx rn-security audit . --fail-on high --format sarif --out rn-security.sarif
```

Package: `@rn-security/cli`. It is a separate package from the auditor library for the same reason
the auditor is separate from the runtime — so that installing one does not drag in the others — and
because a CLI that consumes the library's public API is a genuine test of that API.

## Two rules the whole CLI follows

**It reports; it does not act.** Nothing here edits a file, installs anything, or changes a
project's security configuration (§72). The strongest thing it does is set an exit code, and even
that is opt-in through `--fail-on`.

**It never claims a capability it does not have.** `runtime` says plainly that it cannot check a
device. `dependencies` says plainly that it is not a vulnerability scanner. A command that overstated
its coverage would be worse than the gap it was covering.

## Commands

### `audit [path]`

Every rule, over the whole project. The command a CI job runs.

```sh
rn-security audit .                          # console output, exit 0 unless --fail-on says otherwise
rn-security audit . --fail-on high           # exit 1 when a high or critical finding exists
rn-security audit . --format html -o out.html
```

### `secrets [path]`

Credential detection only — a narrower, faster run for a pre-commit hook. It runs **the same rule**
the full audit runs, not a second implementation: a secrets command that disagreed with the audit
would be worse than no secrets command.

### `dependencies [path]`

Dependency resolution checks: specifiers that are unpinned, or fetched over an unauthenticated
transport. **Not a vulnerability scanner** — advisory data belongs behind a provider interface
fetched at scan time (§38), and a database baked into a release is stale the week it ships. Run
`npm audit`, `pnpm audit` or your platform's scanner alongside it.

### `runtime [path]`

**Project readiness, not a device check.** Root detection, jailbreak detection and the rest run
inside the application on a device; a CLI on a laptop cannot perform them.

What it can do is check the declarations that decide whether those checks return a verdict or an
honest `unknown`, because that failure is silent otherwise:

| Item                                       | Why it matters                                                                                                                      |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `react-native-security-toolkit` dependency | Runtime checks need the package installed                                                                                           |
| `USE_BIOMETRIC` permission                 | Without it the platform refuses the query and every biometric signal is `unknown`                                                   |
| `ACCESS_NETWORK_STATE` permission          | Without it the VPN transport signal is `unknown`                                                                                    |
| `networkSecurityConfig`                    | Makes the cleartext policy explicit rather than a platform default                                                                  |
| `LSApplicationQueriesSchemes`              | The jailbreak package-manager signal cannot be evaluated without it — and declaring it is visible in App Review, so it stays opt-in |
| `NSFaceIDUsageDescription`                 | Face ID is refused without it                                                                                                       |
| `SecurityToolkit.configure({ integrity })` | Three of the four integrity signals report `indeterminate` until the app says what it expects                                       |

Missing items never fail the build: a project may deliberately not use the checks that need them.

### `report <file.json>`

Re-renders a JSON report in another format. Scan once, publish several ways — a job that produced
SARIF and then re-ran the scan for a Markdown comment would be describing two different runs, and
the two would eventually disagree.

```sh
rn-security audit . --format json -o report.json
rn-security report report.json --format markdown -o report.md
rn-security report report.json --format sarif   -o report.sarif
```

The input is validated rather than trusted. A report file is an ordinary file that may have been
edited, and rendering it into HTML puts its contents in front of a reviewer.

### `mcp [path]`

Serves the findings to your AI model over the Model Context Protocol — no API key, no vendor, no
upload. The server is the optional `@rn-security/mcp` package; the command explains how to install it
if it is missing.

```sh
claude mcp add rn-security -- npx -y @rn-security/mcp   # register it with your client
rn-security mcp .                                        # or run it yourself
```

See [mcp.md](../mcp.md) for the tools it exposes and what it refuses to do.

### `rules`

What the auditor actually checks — because a rule id in a suppression file is meaningless unless you
can look it up.

```sh
rn-security rules                       # every rule, with standards and doc path
rn-security rules --category webview
rn-security rules --format json         # includes the MASTG tests that verify each fix
```

## Options

| Flag                     | Effect                                                                     |
| ------------------------ | -------------------------------------------------------------------------- |
| `--format <name>`        | `console`, `json`, `markdown`, `html`, `sarif` (default `console`)         |
| `-o, --out <file>`       | Write to a file instead of stdout                                          |
| `--fail-on <severity>`   | Exit 1 when a finding is this severe or worse                              |
| `--min <severity>`       | Drop findings below this severity from the report (they are still counted) |
| `-c, --config <file>`    | Configuration file, overriding discovery                                   |
| `--include-root`         | Include the absolute project root in the output                            |
| `--color` / `--no-color` | Force colour on or off                                                     |

Colour is on only when a terminal is watching _and_ output is not going to a file. An unknown flag
is an error, never ignored: a mistyped `--fail-onn` that did nothing is how someone comes to believe
a build was gated when it was not.

## Exit codes

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| `0`  | Nothing met the failure threshold                                          |
| `1`  | A finding met `--fail-on`                                                  |
| `2`  | Usage, configuration or target error                                       |
| `3`  | The CLI itself failed — a bug in the tool, not a verdict about the project |

The distinction between **2 and 1** is the one that matters. A configuration mistake and a security
finding are different events, and a pipeline that cannot tell them apart will eventually treat a
broken config as a clean scan. A malformed `security-toolkit.config.ts` exits 2, not 3, because it
is the project's to fix.

Rule errors and an incomplete scan do **not** fail a run. Both are reported loudly in the output, but
neither is a finding, and conflating them would make a flaky timeout look like a vulnerability.

## In CI

```yaml
- name: Security audit
  run: npx rn-security audit . --fail-on high

- name: SARIF for code scanning
  if: always()
  run: npx rn-security audit . --format sarif --min info --out rn-security.sarif
```

This repository does exactly that against itself (§58) — see `.github/workflows/ci.yml`.

## What is not here

- **`--fix`.** Nothing in this toolkit rewrites a project's security configuration (§72). A report
  recommends; a person decides.
- **Watch mode and incremental scans.** A scan of a real React Native app takes well under a second,
  so neither has earned its complexity yet.
- **Diffing against a previous run.** Fingerprints make it possible and the baseline file already
  uses them, but nothing computes "new since last scan".
- **Autocompletion scripts.**
