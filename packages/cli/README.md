# @rn-security/cli

`rn-security` — static security analysis for React Native projects, from the command line.

Part of the [React Native Security Toolkit](https://github.com/programmer443/react-native-security-toolkit).

```sh
npx rn-security audit .                    # every rule, console output
npx rn-security audit . --fail-on high     # exit 1 on a high or critical finding — the CI gate
npx rn-security rules                      # what it checks, and where each rule is documented
```

## Commands

| Command               | What it does                                                                |
| --------------------- | --------------------------------------------------------------------------- |
| `audit [path]`        | Every rule, over the whole project                                          |
| `secrets [path]`      | Credential detection only                                                   |
| `dependencies [path]` | Dependency resolution checks — **not** a vulnerability scanner              |
| `runtime [path]`      | Project readiness for the on-device runtime checks; does not touch a device |
| `report <file.json>`  | Re-render a saved JSON report in another format                             |
| `rules`               | List the rules this build ships                                             |
| `mcp [path]`          | Serve findings to your AI model over the Model Context Protocol             |

Formats: `console`, `json`, `markdown`, `html`, `sarif`. The SARIF is validated against the
specification's own schema and uploads straight to GitHub code scanning.

## Exit codes

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| `0`  | Nothing met the failure threshold                                           |
| `1`  | A finding met `--fail-on`                                                   |
| `2`  | Usage, configuration or target error                                        |
| `3`  | The CLI itself failed — a bug in the tool, not a verdict about your project |

The distinction between 2 and 1 is deliberate: a configuration mistake and a security finding are
different events, and a pipeline that cannot tell them apart will eventually treat a broken config as
a clean scan.

## It reports; it does not act

Nothing here edits a file, installs anything, or changes your security configuration. The strongest
thing it does is set an exit code, and that is opt-in through `--fail-on`.

## Documentation

[Full CLI reference](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/auditor/cli.md)
· [Rules](https://github.com/programmer443/react-native-security-toolkit/blob/main/docs/rules/README.md)

## Licence

MIT © Muhammad Ahmad
