# Example app animations

Lottie animations used by the example app. **The published package has no animation dependency —
these belong to `example/` only**, which is why `lottie-react-native` is an example dev dependency
and never a dependency of `packages/runtime`.

| File                                         | Source                              | Used for                                 |
| -------------------------------------------- | ----------------------------------- | ---------------------------------------- |
| `checking-light.json` / `checking-dark.json` | `kpk_loading_{light,dark}Mode.json` | Querying the native engine (theme-aware) |
| `linked.json`                                | `done.json`                         | Native engine reachable                  |
| `unavailable.json`                           | `alert.json`                        | Native engine unreachable                |
| `vpn.json`                                   | `VPN.lottie`                        | Available; not currently used            |
| `secure-payments.json`                       | `Security pay.lottie`               | Available; not currently used            |

`.lottie` files are dotLottie archives (zipped). The vector animation inside each was extracted to
plain JSON so Metro can bundle it without dotLottie runtime support or an extra `assetExts` entry.

`Password Authentication.lottie` was **not** included: it references 12 external PNG assets rather
than pure vectors, so extracting its JSON alone would render incompletely. Using it would mean
either bundling the image set or enabling dotLottie support in `lottie-react-native`.
