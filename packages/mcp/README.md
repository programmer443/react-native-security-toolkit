# @rn-security/mcp

AI-assisted security review for React Native projects — **without an API key, a vendor, or a source
upload**.

Part of the [React Native Security Toolkit](https://github.com/programmer443/react-native-security-toolkit).

```sh
claude mcp add rn-security -- npx -y @rn-security/mcp
```

Then ask your model to audit the project. It receives the toolkit's findings: severity, confidence,
evidence, remediation, CWE / MASVS / MASWE references with official titles, and the MASTG tests that
verify a fix.

## Why this way

- **No vendor.** It speaks the Model Context Protocol, so the model is whichever one you already use
  — Claude Code, Claude Desktop, an editor, a local model behind an MCP client.
- **No source upload.** The server talks over stdio to a client on your machine and sends nothing
  anywhere.
- **No API key.** There is no credential for this tool to store or leak.
- **Non-authoritative by construction.** Every finding the model sees came from a deterministic rule
  with a stable identifier. A model can interpret a report; it cannot write one or change a severity.

## Tools

| Tool                         | Returns                                                                                  |
| ---------------------------- | ---------------------------------------------------------------------------------------- |
| `security_audit`             | Findings with severity, evidence, remediation, standards references and a coverage block |
| `security_rules`             | Every rule, with categories, standards and documentation paths                           |
| `security_rule_details`      | One rule in full, including the MASTG tests that verify a fix                            |
| `security_runtime_readiness` | Whether the project declares what the on-device checks depend on                         |

All read-only. Nothing writes a file, installs a package, executes project code, or opens a socket.

## What it refuses to do

**Read outside your project.** The model chooses every tool argument, and can be talked into choosing
anything — including by the repository it is auditing. Paths are confined to the server's root.

**Let your code give it orders.** Everything quoted from your repository is labelled as untrusted
data, and injection attempts are reported rather than obeyed — and never rewritten, because stripping
the text would make the scanner lie about what a file contains.

## Any MCP client

```json
{
  "mcpServers": {
    "rn-security": { "command": "npx", "args": ["-y", "@rn-security/mcp"] }
  }
}
```

MCP `2025-06-18` over stdio, implemented directly — no protocol SDK, no transitive dependencies.

## Documentation

[Full MCP documentation](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/mcp.md)

## Licence

MIT © Muhammad Ahmad
