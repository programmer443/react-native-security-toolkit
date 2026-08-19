# Dependency review

Every dependency is a supply-chain decision, and a security tool has less excuse than most for
taking them carelessly. This page lists what each published package installs and why.

## What a consumer installs

| Package                         | Runtime dependencies            | Transitive weight  |
| ------------------------------- | ------------------------------- | ------------------ |
| `react-native-security-toolkit` | **none**                        | 0 packages         |
| `@rn-security/auditor`          | `@babel/parser`, `@babel/types` | ~2 packages        |
| `@rn-security/cli`              | `@rn-security/auditor`          | inherits the above |
| `@rn-security/mcp`              | `@rn-security/auditor`          | inherits the above |

An application that installs only the runtime package downloads **nothing else**. That is the whole
reason the packages are split: a mobile app should not carry a JavaScript parser, and the parser is
the only non-trivial dependency in the project.

## Each dependency, justified

### `@babel/parser` and `@babel/types` — the auditor

The auditor needs an AST for JavaScript, TypeScript, JSX and TSX. Writing one is not a realistic
alternative, and Babel's parser is the one React Native itself uses, so a project already has it in
its tree. It is used in error-recovery mode and never evaluates anything it parses.

`@babel/types` supplies node types only — it is a type-level dependency at runtime.

### What was considered and rejected

| Candidate                   | For                               | Rejected because                                                                                                        |
| --------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `commander` / `yargs`       | CLI argument parsing              | Node's own `parseArgs` covers it; the remainder was thirty lines                                                        |
| `@modelcontextprotocol/sdk` | MCP server                        | Seventeen transitive packages (express, hono, jose, ajv, zod) for HTTP transports and OAuth a stdio server does not use |
| `fast-xml-parser`           | AndroidManifest and plist reading | A restricted scanner that never resolves entities is both smaller and immune to entity-expansion attacks                |
| `glob` / `minimatch`        | Configuration path matching       | Glob libraries have a history of catastrophic backtracking, and this input is attacker-influenced                       |
| `chalk`                     | Console colour                    | Four ANSI constants                                                                                                     |
| An AI vendor SDK            | AI-assisted review                | The MCP server needs no vendor, no key and no upload                                                                    |
| A vulnerability database    | Dependency scanning               | Stale the week it ships; belongs behind a live provider interface                                                       |

### Development-only

`typescript`, `jest`, `babel-jest`, `eslint`, `prettier`, `del-cli`, `react-native-builder-bob`, and
— in the auditor's tests only — `ajv` and `ajv-formats`, used to validate SARIF output against the
specification's own schema. None of these ship.

## Supply-chain posture

- **Lockfile committed**, and CI installs with `--frozen-lockfile`.
- **Install scripts are blocked by default.** `pnpm-workspace.yaml` lists the only package allowed to
  run one, with a comment explaining why. Everything else is inert on install.
- **CI runs with `npm_config_ignore_scripts=true`**, so no dependency lifecycle script executes there.
- **GitHub Actions are pinned to full commit SHAs**, not tags, and each job takes the narrowest
  permissions it needs.
- **Publishing uses npm provenance**, so a released artefact can be traced to the workflow run that
  built it.

## Auditing this yourself

```sh
pnpm install --frozen-lockfile
pnpm ls --prod --depth Infinity --filter react-native-security-toolkit   # expect: nothing
pnpm ls --prod --depth Infinity --filter @rn-security/auditor            # expect: 5 packages
npm pack --dry-run                                                # inspect what would publish
```

## What this page does not claim

Reviewing our own direct dependencies says nothing about the code inside them. `@babel/parser` is
widely used and actively maintained, which is evidence of scrutiny, not proof of safety. If the
parser is compromised, so is the auditor — the mitigation available to you is the lockfile, the
frozen install, and the fact that the mobile runtime package shares none of it.
