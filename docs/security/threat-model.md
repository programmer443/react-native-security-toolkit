# Threat model

What this toolkit protects, who it protects it from, and — as importantly — what it does not defend
against. If a claim is not in here, the project is not making it.

## 1. Assets

| Asset                                      | Where it lives                                          | Why an attacker wants it                   |
| ------------------------------------------ | ------------------------------------------------------- | ------------------------------------------ |
| Authentication tokens, session identifiers | Device storage, memory, logs                            | Account takeover                           |
| Credentials and API keys                   | Application binary, source, storage                     | Direct access to backend systems           |
| Cryptographic key material                 | Keystore / Keychain, or — wrongly — application storage | Decrypting data at rest and in transit     |
| Personal and financial data                | Storage, network, logs, screenshots                     | Fraud, identity theft, regulatory exposure |
| Application integrity                      | The shipped binary                                      | Repackaging, cracking, fraud at scale      |
| Security findings and audit reports        | CI artefacts, pull requests, issue trackers             | A map of where an application is weak      |
| Source code                                | The developer machine and CI                            | Everything above, at once                  |

The last two are the ones a security tool itself puts at risk, which is why they are on this list.

## 2. Threat actors

| Actor                      | Capability                                                                     | What this toolkit does about it                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| **Malicious app user**     | Owns the device; can root or jailbreak it, attach a debugger, hook the process | Runtime checks report indicators with confidence and evidence. They raise cost; they do not stop a determined owner.             |
| **Reverse engineer**       | Extracts and analyses the binary at leisure                                    | Static rules find the secrets and weak cryptography that make this profitable. Nothing prevents analysis itself.                 |
| **Network attacker**       | On-path: hostile access point, operator, proxy                                 | Rules find cleartext endpoints and disabled TLS validation. The runtime reports network posture — it cannot detect interception. |
| **Compromised dependency** | Ships code into the application                                                | Dependency rules find unpinned and unauthenticated resolution. Advisory scanning is explicitly out of scope.                     |
| **Malicious repository**   | Is the thing being scanned                                                     | The scanner treats every input as hostile: §4 below.                                                                             |
| **Malicious contributor**  | Opens a pull request                                                           | Prompt-injection rule finds text aimed at AI reviewers. Ordinary code review remains your job.                                   |
| **Compromised CI job**     | Runs with repository credentials                                               | Out of scope. The toolkit runs _inside_ CI; it cannot defend the runner it runs on.                                              |
| **Insider**                | Legitimate access                                                              | Out of scope.                                                                                                                    |

## 3. Trust boundaries

```text
  React Native JavaScript
            ↕            ← validated at runtime: native payloads are re-checked, not trusted
  Native Android / iOS engine
            ↕            ← platform APIs, which a rooted or jailbroken OS controls
  Operating system
```

The JavaScript layer re-validates every payload crossing the bridge, because on a compromised device
the native side is precisely what an attacker controls. A hooked module can return anything, and a
result that contradicts itself — a `secure` verdict whose own signals report a detection — is
rejected rather than reported.

```text
  Developer repository (UNTRUSTED)
            ↓
  Static scanner  ← never executes, imports, evaluates or installs anything from it
            ↓
  Report          ← escaped per output format; paths percent-encoded in SARIF
            ↓
  MCP client → your AI model  ← content labelled as data, paths confined to the project
```

## 4. The scanned repository is hostile

Every defence here exists because a repository can contain the thing it defends against.

| Threat                                         | Defence                                                             |
| ---------------------------------------------- | ------------------------------------------------------------------- |
| Symbolic link to `~/.ssh`, `/etc`, or a loop   | Links are never followed, and each is recorded                      |
| Enormous or pathological files                 | Per-file, total-byte, depth and time limits, each reported when hit |
| A dylib named `helpers.ts`                     | Binary detection by extension and by content                        |
| `package.json` with install scripts            | Nothing is ever installed or executed                               |
| `security-toolkit.config.ts` with side effects | Parsed and statically evaluated, never imported                     |
| Prompt injection in source                     | Reported as a finding; quoted verbatim, never obeyed                |
| `<script>` in a filename                       | Escaped in HTML and Markdown; percent-encoded in SARIF              |
| A path argument from an AI model               | Confined to the project root by the MCP server                      |

The single most important property: **the scanner never executes target code.** No `import`, no
`require`, no `eval`, no `npm install`, no package script, no spawned process.

## 5. What the runtime checks cannot do

Stated plainly, because the alternative is a false sense of safety:

- **They cannot prove a device is clean.** They report indicators. A device that defeats every check
  is indistinguishable from one that was never compromised.
- **They run inside the process they are protecting.** An attacker with code execution in that
  process can modify the checks themselves. Hook detection is adversarial in this exact way.
- **They are bypassable individually and collectively.** Published tooling exists for defeating each
  category, and this project will never claim otherwise.
- **They cannot detect network interception.** No application can, from inside its own process.
- **They cannot make a decision for you.** The toolkit reports; your policy decides; your server
  should verify independently with attestation.

## 6. What the static auditor cannot do

- **No cross-file data flow.** A credential passed through three functions before reaching storage is
  invisible. Every rule page states what this costs it.
- **Only the JavaScript family is parsed.** Kotlin, Swift, Objective-C, XML, plists and Gradle are
  matched textually — more false negatives, and occasional false positives, than an AST would give.
- **A single hostile file can stall a scan.** Parsing is synchronous and cannot be interrupted; the
  defence is a byte cap, not a timeout.
- **Not a vulnerability scanner.** Dependency advisories are deliberately out of scope; a database
  baked into a release is stale the week it ships.
- **Coverage is what the rules cover.** Fifteen rules is not "every mobile weakness", and a clean
  report means "these rules found nothing".

## 7. The reports themselves are an asset

A findings file travels further than the source it describes — into pull requests, CI logs, issue
trackers, and the context window of an AI model.

- Secrets are **masked** in findings; only a short prefix survives.
- The absolute project root is **omitted by default** from every output format.
- All repository-derived text is **escaped** per format, and percent-encoded in SARIF.
- The MCP server **labels** everything quoted from the repository as untrusted data.

## 8. Privacy commitments

- No telemetry, analytics, device identifiers or advertising identifiers, in any package.
- No hidden network requests. The runtime package makes none at all; the scanner makes none.
- No source-code upload. The AI integration works by handing findings to a client on your machine.
- The only network access in the project is the maintainer-run knowledge sync script.

## 9. Out of scope

Explicitly, so that nobody assumes otherwise:

| Not covered                               | Why                                                   |
| ----------------------------------------- | ----------------------------------------------------- |
| Server-side security                      | Different domain; use appropriate tooling             |
| Compromised build machines and CI runners | The toolkit runs there; it cannot police its own host |
| Dependency vulnerability advisories       | Needs live data; see the dependency rule's page       |
| Obfuscation, anti-tamper packing, RASP    | Different product category                            |
| Formal verification of cryptography       | Rules find misuse of primitives, not flaws in them    |
| Physical device forensics                 | Out of the application's reach                        |

## 10. Reporting a weakness in the toolkit itself

If you find a way to make the scanner execute repository code, escape the MCP path confinement,
produce a report that misrepresents a finding, or make a runtime check report `secure` when it should
not — that is a vulnerability in this project. See [SECURITY.md](../../SECURITY.md); please do not
open a public issue.
