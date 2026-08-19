# Releasing

Four packages, one version, published together from a tag.

## Cutting a release

```sh
# 1. Everything green locally
pnpm verify              # format, lint, typecheck, tests
pnpm build
pnpm security:audit      # the toolkit scans itself

# 2. Bump every package to the same version, and write the changelog section
#    (## [x.y.z] - YYYY-MM-DD) before tagging.

# 3. Preflight — versions agree, tag matches, every package has a readme,
#    a licence, a description and a working bin
pnpm release:check v0.1.0

# 4. Tag and push. The workflow does the rest.
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The `Release` workflow re-runs every CI gate, runs the preflight against the tag, inspects what
would be published, and publishes with `pnpm publish -r` — which resolves `workspace:*` ranges to the
versions being released and publishes in dependency order.

`workflow_dispatch` runs the same job **without publishing**, which is the way to rehearse.

## What the preflight refuses to let through

npm publishes are immutable, and the unpublish window is not a plan. `scripts/check-release.mjs`
fails on:

- packages that disagree on a version, or a version that does not match the tag
- a missing `CHANGELOG.md` section for the version
- a missing `README.md` or `LICENSE` in any package — npm shows both on the package page
- missing `description`, `license`, `repository`, `homepage`, `bugs` or `author`
- `publishConfig.provenance` not set, or a scoped package without `access: public`
- a `bin` entry pointing at a file that does not exist
- a `file:` dependency range, which would resolve to nothing for a consumer

## Requirements

- `NPM_TOKEN` in repository secrets, as an automation token with publish rights.
- The `publish` job holds `id-token: write` so npm can attach **provenance**, linking the artefact to
  the workflow run that built it. Verify it appeared after the first release — the npm page shows a
  provenance badge, and `npm view <package> --json` includes the attestation.
- Every third-party action is pinned to a commit SHA, not a tag.

## Acceptance criteria

The project brief sets the bar for calling anything 1.0. This is where it actually stands.

### Runtime

| Criterion                                                                                                                       | State                                   |
| ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| Android builds; iOS builds; New Architecture works                                                                              | ✅ verified in CI on every change       |
| Root, jailbreak, debugger, emulator/simulator, hook, integrity, secure hardware, biometrics, network, screen checks implemented | ✅                                      |
| Results are structured, with signals, confidence and evidence                                                                   | ✅                                      |
| Platform limitations documented per check                                                                                       | ✅ [docs/runtime](runtime)              |
| **Verified on physical rooted / jailbroken devices**                                                                            | ❌ [outstanding](runtime/validation.md) |

### Static auditor

| Criterion                                                    | State                                                       |
| ------------------------------------------------------------ | ----------------------------------------------------------- |
| JS/TS analysis, native analysis, manifest and plist analysis | ✅                                                          |
| Dependency analysis                                          | ✅ resolution only — advisories are out of scope by design  |
| Secret detection                                             | ✅                                                          |
| Findings deduplicated; suppressions work; severity works     | ✅                                                          |
| OWASP/CWE mapping works                                      | ✅ generated from official sources and validated at startup |

### AI

| Criterion                                                            | State                                                              |
| -------------------------------------------------------------------- | ------------------------------------------------------------------ |
| AI is optional and disabled by default                               | ✅ it is a separate package, and nothing calls a model             |
| Source is redacted / not uploaded                                    | ✅ nothing is uploaded; the MCP server runs locally                |
| Prompt injection is handled                                          | ✅ labelled as untrusted data, reported as a finding, never obeyed |
| AI findings clearly identified; AI cannot control security decisions | ✅ by construction — every finding comes from a deterministic rule |

### Security and privacy

| Criterion                                                 | State                                                               |
| --------------------------------------------------------- | ------------------------------------------------------------------- |
| No telemetry, no hidden network requests                  | ✅                                                                  |
| Malicious repositories cannot execute code                | ✅ [threat model](security/threat-model.md), adversarial test suite |
| No secrets in the package; no arbitrary command execution | ✅ verified by `npm pack` inspection and the self-audit             |
| No dangerous automatic remediation                        | ✅ nothing in the toolkit modifies a project                        |

### Quality

| Criterion                                           | State                               |
| --------------------------------------------------- | ----------------------------------- |
| Unit tests, native tests, integration tests pass    | ✅ 569 tests                        |
| Lint, typecheck, CI pass                            | ✅                                  |
| npm package builds; contents reviewed               | ✅                                  |
| Documentation, SECURITY.md, threat model, changelog | ✅                                  |
| The package can audit itself                        | ✅ `pnpm security:audit`, gating CI |
| No `any` or `@ts-ignore` in security paths          | ✅ none in shipped source           |
| **External security review**                        | ❌ not yet performed                |

### Why this is 0.1.0 and not 1.0

Two criteria are unmet, and both are the kind that cannot be satisfied by writing more code:

1. **No physical-device validation.** The detector logic is tested; the probes underneath it have
   never met a real rooted phone. Until that matrix is filled in, a runtime result is a well-reasoned
   expectation rather than an observed one.
2. **No external review.** The project has been reviewed by the people who wrote it.

A 1.0 that claimed otherwise would be exactly the overclaim this toolkit exists to avoid.
