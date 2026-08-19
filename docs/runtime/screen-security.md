# Screen security

`ScreenSecurity.getStatus()` · `enableProtection()` · `disableProtection()` · check id `screen`

> **The platforms genuinely differ here, and this toolkit does not flatten that.**
>
> - **Android** — `FLAG_SECURE` is real _prevention_. The platform blocks screenshots and screen
>   recordings of a protected window.
> - **iOS** — there is **no public API to prevent a screenshot**. Only detection is possible.
>
> A feature matrix that puts one tick against both platforms is making a claim that is false on one
> of them.

## 1. What it does

Reports whether screen capture protection is currently applied, and lets an application turn it on
and off. This is the only _mutating_ API in the toolkit — everywhere else, the toolkit reports and
the application decides.

## 2. Android

`enableProtection()` sets `FLAG_SECURE` on the current activity's window. The platform then refuses
to include that window in screenshots, screen recordings, or the recent-apps thumbnail.

### `FLAG_SECURE` is per-window, and windows come and go

This is the limitation most likely to catch someone out, so it is worth being exact:

- The flag lives on a **window**, not on the application.
- A window destroyed and recreated — rotation, configuration change, a new activity — **comes back
  without it**.
- **Dialogs and React Native modals create their own windows**, which the toolkit does not own.

The toolkit handles the first two: the desired state is remembered and re-applied through activity
lifecycle callbacks, so protection survives rotation and activity recreation. Setting the flag once
and walking away — which is what a naive implementation does — produces protection that silently
lapses exactly when a user is moving around the app.

It cannot handle the third. A React Native `<Modal>` is a separate window, and protection applied to
the activity does not extend to it. If you display sensitive content in a modal, that content is
capturable. The check result carries this caveat in its metadata so it is visible in a report, not
only in this document.

## 3. iOS

`enableProtection()` currently resolves to `false` on iOS, because there is nothing honest for it to
do yet. Returning `true` would be a lie about a security control, which is worse than doing nothing.

iOS offers **detection** — `UIScreen.isCaptured`, `capturedDidChangeNotification`, and
`userDidTakeScreenshotNotification` (which fires _after_ the screenshot is taken). Those arrive with
the iOS engine in Phase 3, along with an opt-in for the widely used but undocumented secure-text-field
technique, whose fragility will be documented rather than glossed over.

## 4. Signals

| ID                         | Indicator                                                          | Confidence |
| -------------------------- | ------------------------------------------------------------------ | ---------- |
| `RNSEC-ANDROID-SCREEN-001` | Screen capture protection is **not** applied to the current window | high       |

The polarity is worth stating: the signal fires when protection is _absent_, since that is the
condition an application would want to know about.

With no active window — during a cold start, or while backgrounded — the signal reports
`indeterminate`. That is inconclusive, not unprotected.

## 5. Return value of `enableProtection()`

Resolves to whether the change reached a live window:

- `true` — the flag was applied to a window that exists now.
- `false` — either the intent was recorded and will apply when a window appears (a cold start), or
  the platform cannot honour it (iOS today).

Call `getStatus()` if you need to distinguish those. The two are collapsed in the boolean because a
boolean has nowhere to put "recorded but not yet applied".

## 6. False positives and negatives

- Enabling protection **immediately at launch**, before any activity exists, records the intent but
  applies nothing until the first window. `getStatus()` will report `indeterminate` in that gap.
- Protection applied to the activity does **not** cover modals, dialogs, or any window the toolkit
  does not own.
- `FLAG_SECURE` does not stop a photograph of the screen, and never can.

## 7. Recommended application response

```ts
// Turn on before showing sensitive content, off afterwards.
await ScreenSecurity.enableProtection();

// ... show sensitive screen ...

await ScreenSecurity.disableProtection();
```

Enable protection around the specific screens that need it rather than globally. Blanket protection
breaks legitimate screenshots users may want, and — because it does not cover modals anyway — offers
less than it appears to.

## 8. Tests

`android/src/test/java/com/rnsecurity/detectors/screen/ScreenDetectorsTest.kt` — 3 cases: protection
applied, protection absent, and no window to inspect reporting `indeterminate` rather than
unprotected.
