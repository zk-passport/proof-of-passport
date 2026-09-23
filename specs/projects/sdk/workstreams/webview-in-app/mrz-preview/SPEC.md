# MRZ Scan: Black Viewfinder / Apparent Hang (Android demo)

> Last updated: 2026-07-02
> Owner: Justin Hernandez
> Status: Web-side (monorepo) fixes applied and validated on this branch; native
> fixes (self-webview-sdk: preview-overlay diagnosis, NFC method rename) in
> progress in a separate session

## Symptom

In the Android demo (`kmp-sdk-test-app`, `xyz.self.testapp`), the passport MRZ
viewfinder stays black after camera permission and never advances. Looks like a
hang.

## What is actually happening (verified via logcat, 2026-07-02 07:08–07:09)

The scan pipeline is NOT hung. Full sequence observed:

```
07:08:17.170  web → camera setPreviewRect            (sent ×6, incl. before scanMRZ)
07:08:17.170  web → camera scanMRZ
07:08:17.179  native: scanMRZ requested; releasing WebView video before native scan
07:08:17.186  native: startScan preview=true          (AndroidCameraMrzProvider)
07:08:17.264  native: Binding CameraX to back camera
07:08:17 → 07:09:48  ML Kit analyzes frames ~20-30fps; EVERY frame = no_text
07:08:17 → 07:09:48  camera scanProgress events delivered to web (bridge works both ways)
07:09:48      camera closed (user left the screen)
```

Conclusions:

- Bridge request/response, handler registration, CameraX bind, frame analysis,
  and progress events all work. `scanMRZ` never resolves only because ML Kit
  never sees an MRZ.
- 91 straight seconds of `no_text` + user sees black ⇒ **the user has no
  visible camera preview to aim with**. The web `<video>` is dead by design
  (native owns the camera; `releaseWebVideoCapture()` stops web tracks), and the
  native `PreviewView` overlay — despite `setPreviewRect` being sent and the
  overlay path running (`startScan preview=true`) — is not visibly rendering the
  feed where the scan window is.
- So the defect is in the **native preview overlay** added in self-webview-sdk
  commit `45799fa` ("save lifecycle fixes", Jun 30 18:36) — the exact commit
  after which "it was just working" stopped being true.

## Environment (matters — three checkouts are in play)

| Piece                      | Location                                                                                     | State                                                                                          |
| -------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Native SDK the demo builds | `self-webview-sdk` repo, branch `chore/run-android-locally` @ `45799fa`                      | has preview-overlay code, camera+NFC handlers                                                  |
| Web app actually served    | `…/selfxyz/self` checkout @ `68ad0260` + **uncommitted WIP** (vite on :5173, `make web-app`) | WIP = `setPreviewRect` reporting in `MrzScanStatusOverlay.tsx` + `index.html` process polyfill |
| PR 2194 branch head        | `…/selfxyz/selfapp` checkout, 4 commits ahead (`8e98e4d`…`fbaaaea`)                          | **lacks** the `setPreviewRect` WIP and the polyfill                                            |

The demo only positions the native preview because the _dirty_ `self` checkout
is being served. `make web-app` auto-updates the checkout when it has **no**
local changes — one clean checkout and the rect reporting silently disappears.

## Actions

### P0 — find why the overlay isn't visible (self-webview-sdk) — IN PROGRESS (separate session)

File: `kmp-sdk/ocr/src/main/kotlin/xyz/self/sdk/ocr/AndroidCameraMrzProvider.kt`

1. Log the applied rect and view state in `applyPreviewRect()` (left/top/w/h,
   `overlay.isAttachedToWindow`, container class) and log when
   `setPreviewRect` is dropped (`width<=0` early-return is currently silent).
2. Re-run the scan and capture:
   - `adb logcat -s AndroidCameraMrzProvider CameraMrzBridge AndroidWebViewHost`
   - mid-scan: `adb shell uiautomator dump` (or Layout Inspector) — confirm the
     PreviewView's actual bounds, visibility, and that it sits above the WebView.
3. Prime suspects, in order:
   - **Rect scaling**: web reports `getBoundingClientRect() * devicePixelRatio`.
     If the WebView renders at a visual-viewport scale ≠ 1 (Samsung display
     zoom / wide-viewport), physical px ≠ css×dpr and the overlay lands off-
     screen. Compare the logged rect against the WebView's pixel size; if wrong,
     multiply by `window.visualViewport.scale` in the web report.
   - **Coordinate space**: overlay margins are relative to the inset-padded
     wrapper (`previewContainer()`); verify the origin matches the WebView
     viewport origin on-device.
   - **Z-order/rendering**: PreviewView (COMPATIBLE/TextureView) vs
     hardware-accelerated WebView.
4. Add a fallback so a missing/invalid rect can never mean "no preview at all":
   if no valid rect within ~1s of scan start, size the overlay full-screen
   (or at least make the failure loud).

### P0 — stop depending on uncommitted WIP (webview-app, PR 2194 branch) — DONE (2026-07-02, uncommitted on this branch)

1. ~~Commit/port the `self` checkout's uncommitted changes onto the branch~~ Ported:
   - `MrzScanStatusOverlay.tsx` — `setPreviewRect` reporting effect, improved
     over the WIP: reports `visualViewport.scale` (rect-scaling suspect above)
     and falls back to a full-viewport rect if no measurable box within ~1s.
   - `index.html` — `process` polyfill (app blank-screens without it under the
     crypto-browserify alias).
   - NOT ported (intentional): the `self` checkout's `InitialRouteRedirect.tsx`
     force-passport hack — marked local-testing-only in that file.
2. Then converge on ONE checkout for serving; the `self`/`selfapp` split has
   already caused a fix (StrictMode cancel, `53bfd63`) and the WIP to live in
   different working trees of the same branch. (Still open — operational.)

### P1 — web-side resilience (webview-app / webview-bridge) — DONE (2026-07-02, uncommitted on this branch)

1. ~~`camera.scanMRZ` bridge request has no timeout~~ 120s timeout added
   (`webview-bridge/src/adapters/camera.ts`). On timeout the viewfinder catch
   routes to `/capture/passport/nfc-error` (`stage: 'mrz'`), whose Start Over
   CTA restarts the capture flow.
2. ~~Viewfinder unmount never tells native to stop~~ Both viewfinder routes now
   fire `camera.stopCamera` on unmount, deferred one tick so StrictMode's
   cleanup→setup remount cancels the stop and keeps the live scan. The camera
   adapter additionally fires `stopCamera` whenever `scanMRZ` rejects (timeout
   included), so a dead request can never orphan the native scan — on-device
   logcat (08:09–08:11) showed the camera streaming 2 min past a timed-out
   request and its late result dropped as "No pending request". Native
   `stopCamera` handler exists and is idempotent.
3. ~~`waitForBox` rAF-loops forever~~ Falls back to the full-viewport rect
   after ~1s if no measurable `<video>` box appears.
4. MRZ-stage failures no longer show the chip-error copy: both `NfcErrorRoute`s
   pass an MRZ-specific `copy` override to `PassportNfcErrorScreen` when
   `stage === 'mrz'` (`onboarding/components/nfcErrorCopy.ts`).

Tests: 2 new webview-bridge adapter tests (scanMRZ rejection fires stopCamera;
120s fake-timer timeout rejects + fires stopCamera) and 2 new webview-app flow
tests (MRZ failure → error route with camera copy + stopCamera; unmount
mid-scan → stopCamera), plus a chip-copy assertion on the NFC-failure flow.
Validated: `webview-bridge` build + tests (70), `webview-app` tsc + vite build

- eslint + tests (256) all pass.

**Serving gap (why on-device still failed at 08:09):** vite :5173 serves the
`self` checkout, which lacks all of the above. Sync these files from `selfapp`
to `self` (or repoint serving), then rebuild `self`'s `webview-bridge` dist:
`packages/webview-bridge/src/adapters/camera.ts`,
`.../src/__tests__/adapters.test.ts`, and under
`packages/webview-app/src/screens/onboarding/`: `components/MrzScanStatusOverlay.tsx`,
`components/nfcErrorCopy.ts` (new), `passport/CodeScanViewfinderRoute.tsx`,
`eu-id/ViewfinderRoute.tsx`, `passport/NfcErrorRoute.tsx`, `eu-id/NfcErrorRoute.tsx`.

### P1 — NFC method mismatch (will hit immediately after MRZ works) — monorepo half DONE; self-webview-sdk half IN PROGRESS (separate session)

- Web sends `nfc`/`scanPassport` (`webview-bridge/src/adapters/nfc-scanner.ts:21`).
- `self-webview-sdk` `NfcBridgeHandler` (android + ios) only handles `"scan"`
  → METHOD_NOT_FOUND at the NFC step.
- The staged `"scan" → "scanPassport"` rename in the **monorepo's**
  `packages/kmp-sdk/.../NfcBridgeHandler.kt` does not reach the demo — the demo
  builds `self-webview-sdk`'s copy. Apply the same rename there (accept both
  method names during the transition if other web builds still send `scan`).

### P2 — repo hygiene

- Two divergent `kmp-sdk` trees exist (monorepo `packages/kmp-sdk` vs
  `self-webview-sdk/kmp-sdk`). The monorepo copy registers no camera/NFC
  handlers at all; edits there don't affect the demo. Declare
  `self-webview-sdk` canonical for the demo (or set up syncing) so staged
  changes stop landing in the inert copy.

## Verification (once fixes land)

1. `make web-app` (serving the PR branch, clean tree) + rebuild/install the
   Android demo from `self-webview-sdk`.
2. Passport onboarding → viewfinder: camera feed visible inside the scan
   window; pill shows progress states.
3. Aim at a passport MRZ → `mrz_detected` → auto-navigates to NFC screen.
4. NFC scan starts without METHOD_NOT_FOUND (logcat clean).
5. Kill test: leave the viewfinder mid-scan → `stopCamera` fired, camera LED off.
