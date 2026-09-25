# App → WebView Full Cutover — Migration Research & Plan

> Last updated: 2026-07-20
> Owner: SDK / Platform
> Status: Research (pre-implementation inventory; not an execution doc yet)
> Parent: `../SPEC.html` (WebView-in-App)

## Context

Today `app/` (Self wallet) runs the **entire** verification flow natively (via `@selfxyz/mobile-sdk-alpha` + app screens + app-vendored NFC/MRZ native). The WebView SDK path (`@selfxyz/rn-sdk` → `webview-app`) exists but is **dev-only**, gated behind a hardcoded flag. "Full cutover" = make the WebView the default for all flows and all existing users, then retire app's redundant native/UI. This doc inventories every detail that must be handled first, from a 5-dimension subagent sweep.

## Two premises corrected (were overstated in earlier analysis)

1. **Native modules are the SAME source lineage, not a reimplementation.** The `xyz.self.sdk:nfc`/`:ocr` AARs are vendored from the same private repos the app clones (`react-native-passport-reader`, `android-passport-nfc-reader`) and, for iOS MRZ, ported from `app/ios`. iOS NFC is the **identical commit** (`b478e1f`). ⇒ There is **no jMRTD version parity gate** for NFC (my earlier "0.7.35 vs 0.8.1" mis-mapped the OCR module's jMRTD onto the NFC path; the app's actual NFC bridge already runs jMRTD 0.8.1 + BouncyCastle, same as the AAR).
2. **Proving is relocated, not rebuilt.** Both app and `webview-app` drive the *same* `mobile-sdk-alpha` proving state machine (`useProvingStore`/`provingMachine`); app uses the RN entry, webview-app the `/browser` entry (WV-07, Done). The ZK proof runs remotely in a TEE over a socket.io tunnel — native never proved. Cutover just moves the *driver* into the WebView.

## Hard blockers (must be designed/resolved before default cutover)

| # | Blocker | Evidence | Why it blocks |
|---|---|---|---|
| B1 | **Relayer completion broken in WIA path (split-brain socket)** | webview-app never calls `startAppListener` (`selfAppContext.ts`), so its relayer socket is null; `provingMachine.handleProofResult` no-ops. Host holds the live socket but `WebViewHostScreen.onSuccess` only `Alert`s. No bridge domain carries the emit. | The requesting website is **never notified of proof success**. Core product function silently broken. |
| B2 | **Existing-user identity/document migration** | Crypto is compatible (same BIP32 path `m/44'/60'/0'/0/0` ⇒ same key ⇒ same onchain commitment), but storage differs: app `secret` (ethers Mnemonic **object**) vs webview `self_sdk_self_mnemonic` (**bare phrase**); docs `documentCatalog`/`document-{hash}` vs `self_sdk_self_document_catalog`/`self_sdk_self_doc_{hash}`; cloud backup stores object vs phrase. | Naive switch **mints a new identity + shows zero documents** → user looks unregistered; re-registration can be nullifier-rejected. Catastrophic without a one-time keychain migration or a translating bridge. |
| B3 | **Two overlapping `xyz.self.sdk:shared` sources** | rn-sdk's `compileOnly shared-android:0.1.0` resolves from **vendored `packages/kmp-sdk`** (mavenLocal, published by app setup); capture AARs' `shared` resolves from **self-sdk-dist**. | Two `shared` variants in one graph. Needs one source → gated on **SD-07** (decommission vendored kmp-sdk), itself blocked on WIA-17 canonical-home decision. |
| B4 | **Android webview-bundle delivery unwired** | iOS resolves the embedded bundle via `bundleRootUri`; Android has no `sourceSets`/copy task to place `self-wallet` in `android_asset`. RSP-05 (Expo plugin) deferred. | Android production can't load the WebView. Must land RSP-05 or a Gradle copy task. |
| B5 | **NFC AAR is a stale snapshot behind the app** | AAR `io.tradle.nfc.PassportReader` is a pre-`f0ec7ea` vendor (479 lines); app is ahead (585 lines) with Active Authentication + CAN→MRZ fallback (`f0ec7ea`, `bed5a51`). | Adopting the AAR as-is is a **functional NFC regression**. AAR must be re-vendored/forward-ported to ≥ `f0ec7ea` before app depends on it. (This is the real "gate" — a freshness gate, not a version gate.) |

## Dimension findings

### 1. Native (same lineage; reconciliation = dedup + freshness)
- iOS NFC: identical `b478e1f` — no work beyond **not double-linking** `SelfNFCPassportReader` (pod vs SDK xcframework).
- iOS MRZ: same Vision engine ported from app; only diff is QKMRZParser → hand-written `MrzParser`. Swap `QKMRZScanner` out at cutover.
- Android NFC: same stack (jMRTD 0.8.1/BouncyCastle) but AAR **behind** app (B5). Duplicate `io.tradle.nfc.*` classes if both present → must exclude one.
- Android MRZ: same jllarraz code repackaged; deltas = ML Kit artifact (`play-services-mlkit-text-recognition:18.0.2` vs `com.google.mlkit:text-recognition:16.0.1`) + jMRTD unification.
- Crypto/keychain/biometrics/QR: no parity work (SelfCrypto isn't an app dep; keychain/biometrics are standard RN packages; QR is app-owned, host-side).

### 2. Flow / proving parity (~70 screens each; most real)
- Real & wired: onboarding, country/id pick, passport MRZ+NFC (via bridge), registration, disclosure, disclose result, EU-ID capture, manage-docs, points.
- Gaps: **KYC** (WV-05 In Progress, needs Didit rework; WV-06 Ready), **Proof history is `MOCK_PROOF_HISTORY`** (stubbed), **recovery/backup** (WV-17, SELF-2504 In Progress; cloud-backup parity unverified), Aadhaar upload depth, EU-ID helper (WV-10 Deferred), dev tooling (low priority). Production mocks still present (`mockDocumentStore` on Home, `MockRegistrationFailureButton`). Several proving specs (WV-08/09/11/12) built but not certified Done.

### 3. Identity / storage (B2) — IMPLEMENTED via translating handler (Option B), `feat/wia-b2-securestorage-translator`
Chose Option B done cleanly via **handler injection** (no copy, no migration flag, no drift, legacy stays the single biometric-gated source of truth):
- rn-sdk: `secureStorage` handler is now **host-injectable** (`SecureStorageStore` + `secureStorage?` prop on `SelfVerification`, mirroring `documents`); default stays `KeychainHandler`. Additive/opt-in — no bridge-protocol change; KMP path (`useKmpBridge` intercepts `secureStorage` before the router) untouched.
- app: `WebViewHostScreen` provides `app/src/providers/webViewSecureStorageAdapter.ts`, mapping the WebView's `self_*` keys to the legacy `secret`/`documentCatalog`/`document-{contentHash}` for get **and** set (content-hash doc ids kept; WebView treats `doc.id` as opaque). Reuses `authProvider` (`getStoredMnemonicPhrase`/`restoreMnemonicPhrase`) + `passportDataProvider` primitives. `requireBiometric` honored → secret keeps strong protection.
- **Identity write-guard:** `set('self_mnemonic'/'self_private_key')` never overwrites an existing `secret` (prevents biometric-cancel-then-mint from clobbering the identity). Registration state re-derives on-chain as before. Cloud backup untouched (restore writes legacy `secret`, read via the translator).
- Parity guard test pins WebView `derivePrivateKey` to the standard BIP44 key (== ethers), so the translated key == the existing identity.
- **Path-A follow-up (deferred):** when `secureStorage` migrates to the KMP transport, re-inject the same translation as a host `SecureStorageProvider` via `SdkProviderRegistry` (the `==null` hook in `SelfBridgeModule.kt`). Alternatives A (one-time copy) rejected: duplicates the secret into a weaker non-biometric `self_sdk_*` store.
- Original options considered: A (one-time host keychain copy) / B (translating bridge). Both must precede the first `ensureSecret()`/document read.

### 4. Host integration / cutover surface
- **Flag**: `IS_WIA_ENABLED` — hardcoded `false` in `app/src/utils/devUtils.ts:24`. Only two gates read it: `SplashScreen.tsx` (cold start) and `deeplinks.ts:214` (selfApp branch). **Not gated**: QR-scan entry (`QRCodeViewFinderScreen`), `sessionId`-only + `mock_passport` deeplink branches. Must become a staged/remote flag before defaulting on.
- **WebViewHostScreen wired**: request, `mode`, analytics, documents (keychain adapter), `onGoBack`, `onReferenceId`, `onLoadDiagnostic`, loading/error, `bundleRootUri`, native capability handlers auto-resolve.
- **Stubbed/missing**: `onSuccess`/`onFailure` are `Alert` stubs (B1); `navigation.onGoTo` unwired; **no external-browser/`openURL` bridge domain**; **no push-notification registration bridge**; `logNfcEvent` sink missing; host redundantly opens & orphans the relayer socket.
- Bridge domains present: `nfc, biometrics, secureStorage, camera, crypto, haptic, analytics, lifecycle, documents, navigation`.

### 5. Build / release / footprint
- Android native = runtime-cloned private repos (`setup-private-modules.cjs`, auth `SELFXYZ_APP_TOKEN`); iOS = git pods. app does **not** bundle webview-app today (only the dev screen loads it).
- To consume AARs: add `self-sdk-dist` Maven repo + `SELF_SDK_GITHUB_TOKEN` to `app/android/build.gradle` `allprojects` and EAS/CI; EAS is a POC (`eas.json` single `poc` profile) — production is GitHub Actions + fastlane.
- Dedup at cutover: remove app's `jmrtd:0.7.35`, `:react-native-passport-reader`, `:passportreader`, `QKMRZScanner`, direct `SelfNFCPassportReader` pod, direct ML Kit text-recognition; strip the two clones from `setup-private-modules.cjs`; keep `:mobile-sdk-alpha`, `jp2-android` exclusion, barcode force. Re-run `check-16kb-alignment.sh` on the AAR AAB.
- Size: ~58 MB webview bundle rides along; net size improves only after vendored native removed.

## Minimal version (small, non-destructive — reasonable next step)
Prove the scaffolded path completes **one** real flow on device behind the flag, without touching production users:
1. Flip `IS_WIA_ENABLED` in a dev build; route a `selfApp` deeplink to `WebViewHostScreen`.
2. Replace the `onSuccess`/`onFailure` `Alert` stubs with real handling **including the relayer emit** (call the host's `getSelfAppState().handleProofResult(...)`), resolving B1 for this one path.
3. Reuse app's existing native modules (NfcHandler name-fallback) — no AAR swap, no native removal.
4. Drive one disclose end-to-end on device for a test user. No storage migration (new user only).

This validates B1's fix and the bridge round-trip cheaply; it does **not** touch B2/B3/B4/B5.

## Suggested phasing (full replacement)
1. **Unblock foundations**: B3 (SD-07 / single `shared`), B4 (Android bundle delivery), B5 (refresh NFC AAR to ≥ `f0ec7ea`). Certify WV-08/09/11/12 Done; remove production mocks.
2. **Close host gaps**: relayer-emit bridge domain (B1), real onSuccess/onFailure with post-verification parity, gate QR + remaining deeplink branches, external-browser + push bridges, `onGoTo`, promote the flag to staged/remote.
3. **Finish flows**: KYC (WV-05/06), proof-history real data, recovery/backup (WV-17/SELF-2504), Aadhaar depth.
4. **Identity migration (B2)**: implement + heavily test Option A (or B) with real registered users; verify derived key == existing key (commitment unchanged); backup translation.
5. **Build cutover**: adopt AARs, dedup native, EAS/CI auth, size check; staged rollout via the flag; retire app native + UI once parity + migration proven.

## Implementation status (branch `feat/wia-app-cutover`)
- **B1 relayer completion (SELF-3583) — DONE (committed).** Host owns the single relayer socket; `WebViewHostScreen.onSuccess/onFailure` emit `proof_verified`/`proof_generation_failed` via `getSelfAppState().handleProofResult`, guarded by a `sessionId` correlation check and socket teardown on unmount. Also fixed `LifecycleHandler.setResult` reading only flat `errorCode/errorMessage` (WebView sends nested `error:{code,message}`, so failures previously fell through to `onCancelled`). On-device TODO: verify the emit flushes before the unmount disconnect; confirm end-to-end `sessionId` correlation.
  - **PR #2221 review hardening (committed):** analytics no longer logs raw session ids on mismatch (emits `request_session_match: false`); unmount teardown is guarded so a newer deeplink's socket isn't torn down and a just-emitted result isn't discarded before socket.io flushes it.
  - **B1 follow-up — SELF-3638 (emit on proving-terminal), IMPLEMENTED (`feat/wia-relayer-terminal-emit`).** Relay completion was coupled to the result-screen Continue button, so closing the app after proving-terminal but before Continue never notified the website (Codex #2221). **Resolution — reuse the production path, no new socket/dep:** the relayer socket is already single-owned by the host's production `SelfClient`/`selfAppStore` (module singleton), and `WebViewHostScreen.emitRelayerResult` already emits via `getSelfAppState().handleProofResult`. So the fix is only (1) the WebView reports its terminal result at proving-completion — `ProofGenerationRouteScreen` calls `lifecycle.setResult` at each terminal state (self-app-only route; embed uses a disjoint path) and passes `resultSent: true` so the button dedups; and (2) the host decouples emit from navigation — `handleSuccess`/`handleFailure` only emit (no `goBack`), navigation moves to `dismiss → onCancelled`, and `emitRelayerResult` is idempotent. Earlier options rejected: A (WebView owns a socket — weakest resilience) and C (rn-sdk owns a new socket / mobile-sdk-alpha dep — duplicates the production relayer contract; `useSelfAppStore` isn't even exported). Closes SELF-3583 AC-2.
- **B4 Android bundle delivery (SELF-3586) — DONE (committed).** rn-sdk android library adds a guarded `assets.srcDirs += ../assets` so `self-wallet` merges into any consumer's `android_asset` (no host wiring). Follow-up: remove the test-app's now-redundant manual asset srcDir to validate the truly-unwired path.
- **Proof history (SELF-3589) — REVERTED, needs redo. Do NOT persist to `secureStorage`.** An initial pass stored a `self_proof_history` array via the secureStorage bridge; this was reverted by direction. `ProofHistoryScreen.tsx` is back on `MOCK_PROOF_HISTORY`. Key constraint for the next agent: the webview runtime has **no** proof-history data source today — no persistence/write path, and neither `@selfxyz/mobile-sdk-alpha` nor `@selfxyz/webview-bridge` expose a history API; the app reads a **native SQLite DB** (`app/src/stores/database.ts` via `useProofHistoryStore`) unreachable from the WebView. Options to evaluate (not secureStorage): (a) a new history **bridge domain** so the WebView reads the host's native SQLite store (single source of truth); (b) fetch history from the **relayer/backend**; (c) promote a shared history store into `@selfxyz/mobile-sdk-alpha` usable from both the RN and `/browser` entries. Ties to B1 for relayer status-sync (pending→terminal).

## Open decisions
- SD-07 canonical home (WIA-17): vendored `packages/kmp-sdk` vs external `self-webview-sdk` — determines B3. **Explicitly unresolved as of 2026-08-09; owner: Seshanth Saravanakumar** ([SELF-3708](https://linear.app/selfprotocol/issue/SELF-3708), [SD-07 Open Decision 1](../../sdk-distribution/plans/SD-07-decommission-vendored-kmp-sdk.md)).
- ~~Bundle vs hosted-URL (SD-01–05)~~ — **settled for this surface: embedded bundle only.** [OVERVIEW.md](../../../OVERVIEW.md) rejects hosted-URL/OTA for the app WebView on security grounds. The ~58 MB is accepted; [#2232](https://github.com/selfxyz/self/pull/2232) strips it from store builds until WIA ships. SD-01–03 hosted loading stays live **for the external native shells only** — it is not a pending option here.
- Storage migration Option A (copy) vs B (translating bridge).
- Whether app removes vendored native immediately or runs both during a transition (accepting dedup risk).

## Key files
`app/src/utils/devUtils.ts`, `app/src/screens/dev/WebViewHostScreen.tsx`, `app/src/navigation/{deeplinks.ts,index.tsx}`, `app/src/screens/app/SplashScreen.tsx`, `app/src/providers/{authProvider,passportDataProvider}.tsx`, `app/src/services/cloud-backup/*`, `app/scripts/setup-private-modules.cjs`, `app/ios/Podfile`, `app/android/{settings,build}.gradle`, `app/android/app/build.gradle`, `packages/rn-sdk/src/{SelfVerification.tsx,handlers/*,bundlePath.ts}`, `packages/webview-app/src/utils/{secretManager.ts,selfAppContext.ts}`, `packages/webview-bridge/src/{types.ts,adapters/*}`, `packages/mobile-sdk-alpha/src/{stores/selfAppStore.tsx,proving/provingMachine.ts}`, `specs/.../sdk-distribution/plans/SD-07-decommission-vendored-kmp-sdk.md`.
