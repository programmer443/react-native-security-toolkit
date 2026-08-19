# Security knowledge layer

Every standards identifier the auditor can print — CWE, MASWE, MASVS, MASTG — comes from a
**versioned snapshot generated from the official sources**. None of them is typed by hand.

## 1. Why it is generated

`MASWE-0104` looks exactly as plausible as `MASWE-0004`. So does `CWE-793`. A security report that
cites an identifier which does not exist is worse than one that cites none: it reads as rigour, and
the reader has no way to tell without looking it up.

§32 forbids fabricated identifiers, and the only reliable way to honour that is to make fabrication
impossible rather than discouraged:

- The snapshot is **generated** by `packages/auditor/scripts/sync-knowledge.mjs` from upstream
  repositories and MITRE's own catalogue.
- Rules carry **identifiers only** — never a title, never a paraphrase of a standard (§33). Titles
  are looked up from the snapshot when a finding is built.
- Identifiers are **validated at rule registration**. A rule citing something absent from the
  snapshot throws before any scan starts.

## 2. Sources

| Standard | Source                                                              | What is captured                                                              |
| -------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| MASVS    | `github.com/OWASP/masvs` → `OWASP_MASVS.yaml`                       | Control id, group, and the control statement                                  |
| MASWE    | `github.com/OWASP/maswe` → `weaknesses/**/MASWE-*.md` front matter  | Weakness id, title, and the MASVS/CWE mappings upstream declares              |
| MASTG    | `github.com/OWASP/mastg` → `tests/**`, `tests-beta/**` front matter | Test id, title, platform, and the weakness it verifies                        |
| CWE      | `cwe.mitre.org/data/definitions/<id>.html`                          | Identifier and official name, for every entry a weakness or a rule references |

Each run pins the three repositories to an exact commit and records it, along with the CWE catalogue
version, in `SOURCES.md` beside the snapshot.

Only identifiers, titles and mappings are captured. No prose from any standard is copied, so the
snapshot is a lookup table rather than a redistribution.

## 3. The snapshot is committed

Generated **and** committed, deliberately:

- **Committed**, because a scan must work offline and produce the same report in six months. A
  knowledge layer fetched at scan time makes reports depend on the network and on whatever upstream
  looked like that morning.
- **Generated**, because the moment a human edits it, the project has started inventing standards
  references.

Snapshot `2026.1` — the one this build ships — contains 24 MASVS controls, 78 MASWE weaknesses, 181
MASTG tests and 101 CWE entries (CWE catalogue 4.20).

## 4. Regenerating

```sh
pnpm --filter @rn-security/auditor knowledge:sync
```

The script writes generated TypeScript modules plus `SOURCES.md`, and nothing else. It executes
nothing it downloads: archives are read in memory, never extracted to disk, so a malicious path
inside one has nowhere to land.

Review the diff before committing. This is standards data, and a large unexplained change means
upstream restructured something.

## 5. What the layer gives a finding

```ts
import { knowledge } from '@rn-security/auditor';

knowledge.cwe('CWE-798'); // { id, name: 'Use of Hard-coded Credentials' }
knowledge.maswe('MASWE-0004'); // title, plus the MASVS and CWE ids it maps to
knowledge.mastgTestsFor('MASWE-0001'); // the MASTG tests that verify this weakness
```

`mastgTestsFor` is what lets a report answer _"how do I verify the fix?"_ with a real test identifier
instead of a paragraph of advice (§40). Not every weakness has MASTG coverage; when it has none, the
answer is an empty list rather than an invented test id.

## 6. Mapping confidence

Every rule declares one of `low`, `medium`, `high` for its mapping, defaulting to `medium`. It
appears on each reference in the finding.

This exists so that an arguable mapping can be published as arguable. `RNSEC-DEPS-001` maps to
MASWE-0044 at `medium`, because that weakness is about dependencies with _known vulnerabilities_,
which overlaps with but is not identical to unpinned resolution. §32 asks for exactly that: mark the
uncertainty, or omit the mapping — never dress it up.

## 7. Limitations

- **A snapshot is a moment in time.** Upstream renumbers `tests-beta` entries; those are marked
  `beta` in the snapshot so a rule author can see the risk before pinning to one.
- **CWE names only.** Relationships, likelihoods and mitigations from the CWE catalogue are not
  captured; the auditor needs the identifier and the name.
- **One snapshot per build.** `KnowledgeIndex` can be constructed over any snapshot, so pinning an
  older one is possible, but only the current snapshot ships.
- **Mappings are rule-declared, not derived.** The architecture proposal envisaged a separate
  `mappings.json`; in practice a rule declaring its own identifiers — validated against the snapshot
  — keeps the mapping next to the detection logic that justifies it, with no second file to drift.
  The constraint that matters (no unverified identifier reaches a report) is enforced either way.
