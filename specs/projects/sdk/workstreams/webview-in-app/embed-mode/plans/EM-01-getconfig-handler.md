## EM-01: SDK — implement `lifecycle.getConfig`

> Last updated: 2026-06-29
> Status: Draft

- Workstream: Embed Mode
- Backlog ID: EM-01
- Branch: TBD (off `dev`)
- PR: TBD

### Why

- The `getConfig` mode contract is **already settled** in
  `../../SPEC-MODES.html` and **live for the RN host** (WIA-16, Done). EM-01 does
  not design a new contract — it brings the `self-webview-sdk` KMP/Swift shell to
  parity. `getConfig` is implemented by no KMP/Swift host today (verified: zero
  matches in `self-webview-sdk`), so embed mode is unreachable against **that
  shell specifically**.
- **Not on the demo path.** The demo unblock is EM-02 Part A (doc-aware routing),
  which works at the web catch-all regardless of `getConfig`. EM-01 is the proper
  follow-up that lets the embed surface activate against the KMP/Swift shell.
- Producer-before-consumer (for EM-02 Part B): shipping the SDK handler gives the
  web's getConfig-consumption work something real to verify against.
- The SDK Activity already holds everything `getConfig` must return — it decodes
  `SelfSdkConfig` + `VerificationRequest` from intent extras in
  `SelfVerificationActivity.initVerificationFlow()`. This plan just exposes them.

### ⚠ Before implementing (parity TODO — not yet reflected below)

- **Mirror `packages/rn-sdk/src/handlers/LifecycleHandler.ts` field-for-field**
  (the live RN reference: `{ mode, verificationRequest: config.request, debug,
platform, referenceId }`). Do NOT re-derive the shape from KMP's
  `VerificationRequest`/`SelfSdkConfig` types — the WebView must not be able to
  tell which shell it runs in. Verify field names against the RN object,
  especially RN's flat `config.request` vs KMP's separated config/request.
- **Keep `referenceId`** as an optional pass-through (RN emits it; WIA-14 threads
  it). The earlier "drop referenceId" guidance below is **wrong** — omitting the
  field diverges from the settled contract. Re-pin the contract section to the RN
  shape before coding.

### Scope

- Add a `getConfig` method to the lifecycle bridge handler on **both** platforms
  (`androidMain` + `iosMain` — there is no commonMain lifecycle handler).
- Return `{ mode: "embed", verificationRequest: {…}, debug, platform }` per the
  contract in `../SPEC.md`. When launched via the SDK, mode is **always `embed`**
  (the verification Activity/host only exists for SDK-driven verification).
- Define the response payload as a **commonMain serializable model + builder** so
  both platforms share one encoding and field set, and add a commonTest for it.

### Out of Scope

- Web-side consumption + doc-aware boot routing (EM-02, `self` repo / `wia-demo-rd1`).
- The `/tunnel/tour/1` ↔ web-route reconciliation (handled in EM-02; see SPEC Q2).
- Changing `QueryParamsBuilder` / removing URL params (keep the URL path working
  until the web fully switches to `getConfig`; remove later, not here).

### Files to Modify

| File                                                                                     | Change                                                                                                                                             | Notes                                                                 |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `kmp-sdk/shared/src/commonMain/kotlin/xyz/self/sdk/handlers/HostConfig.kt` (new)         | Add `@Serializable HostConfigResponse` + `buildGetConfigResponse(config, request): JsonElement` that encodes the SPEC field set.                   | Shared by both platform handlers; single source of the payload shape. |
| `kmp-sdk/shared/src/androidMain/kotlin/xyz/self/sdk/handlers/LifecycleBridgeHandler.kt`  | Take `config: SelfSdkConfig` + `request: VerificationRequest` in ctor; add `"getConfig" -> buildGetConfigResponse(config, request)` to the `when`. | Currently only `ready`/`dismiss`/`setResult`.                         |
| `kmp-sdk/shared/src/iosMain/kotlin/xyz/self/sdk/handlers/LifecycleBridgeHandler.kt`      | Same ctor + `getConfig` branch.                                                                                                                    | Keep parity with Android.                                             |
| `kmp-sdk/shared/src/androidMain/kotlin/xyz/self/sdk/webview/SelfVerificationActivity.kt` | Thread the already-parsed `config` + `request` into `LifecycleBridgeHandler(...)` in `registerHandlers()`.                                         | They're locals in `initVerificationFlow()`; pass them through.        |
| `kmp-sdk/shared/src/iosMain/kotlin/xyz/self/sdk/api/SelfSdk.ios.kt`                      | Construct the iOS `LifecycleBridgeHandler` with config + request.                                                                                  | Mirror Android wiring.                                                |
| `kmp-sdk/shared/src/commonTest/.../handlers/HostConfigTest.kt` (new)                     | Assert the builder emits mode=embed + every SPEC field for a populated request, and stable defaults (`disclosures=["ofac"]`, empty arrays).        | Hermetic.                                                             |
| `kmp-sdk/shared/src/androidUnitTest/.../handlers/LifecycleBridgeHandlerTest.kt`          | Add a `getConfig` case: handler returns the encoded payload; unknown method still throws.                                                          | Extend existing test.                                                 |

### Implementation Steps

1. **commonMain payload model + builder.** Define `HostConfigResponse`
   (`mode`, `verificationRequest`, `referenceId?`, `debug?`, `platform?` — match
   RN's `LifecycleHandler.ts` shape, see "Before implementing") and a
   `VerificationRequestPayload` carrying **raw** `VerificationRequest` fields + the
   `QueryParamsBuilder`-encoded `SelfSdkConfig` fields (endpoint, appEndpoint
   [RAW — do NOT normalize; the web does], environment=`environment.queryValue`,
   endpointType [same default logic as QueryParamsBuilder], appName,
   chainID, `version = config.version` [NOT hardcoded]). Provide
   `buildGetConfigResponse(config, request, platform): JsonElement`.
   **Keep `referenceId?`** as an optional pass-through (RN parity — see "Before
   implementing"). Do **not** include `targetOrigin`/`proofItems`/`timestamp` —
   see the "Deliberately NOT in the contract" list in `../SPEC.md`.
2. **Android handler.** Add `config`/`request` ctor params; route
   `"getConfig"` to the builder (`platform = "android"`).
3. **Android wiring.** In `SelfVerificationActivity.registerHandlers()`, pass the
   parsed `config`/`request` into `LifecycleBridgeHandler(...)`. (They are already
   decoded earlier in `initVerificationFlow()`.)
4. **iOS handler + wiring.** Same ctor + `getConfig` branch; construct with
   config/request in `SelfSdk.ios.kt` (`platform = "ios"`).
5. **Tests.** commonTest for the builder; extend the Android
   `LifecycleBridgeHandlerTest` for the `getConfig` method.

### Validation

```bash
# Canonical (repo root Makefile) — runs the kmp jvm/android/ios unit suites:
make test-kotlin
# Manual bridge check (device/emulator), watching the round-trip:
# adb logcat | grep -iE "lifecycle|getConfig"
#  → web OperatingModeProvider resolves getConfig < 800ms, mode='embed'
```

### Definition of Done

- [ ] `getConfig` implemented on android + ios; shared commonMain builder.
- [ ] Returns mode=embed + full SPEC field set; defaults correct.
- [ ] commonTest + Android handler test pass; existing lifecycle tests green.
- [ ] No change to `ready`/`dismiss`/`setResult` or to self-app fallback (a host
      without `getConfig` still rejects → web stays self-app).
- [ ] Backlog row EM-01 → Done; PR linked; Linear issue created.

### Status Log

- 2026-06-29: Drafted. Contract defined in `../SPEC.md`; verified `getConfig` is
  absent from the SDK and called (unimplemented) by the web on both `main` and
  `justin/wia-demo-rd1`.
- 2026-06-29: Demo host confirmed (self-webview-sdk PR #26, KMP test app) — it
  launches a real `VerificationRequest` but implements **no `getConfig`**, so the
  demo runs in self-app mode and EM-01 is **not** on the demo path. Parked; the
  demo unblock is EM-02a (catch-all routing). Before picking this up, do the RN
  parity re-pin (see "Before implementing" above).
