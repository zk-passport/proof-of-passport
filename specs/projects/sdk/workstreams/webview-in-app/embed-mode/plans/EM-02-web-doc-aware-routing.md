## EM-02: Web — doc-aware embed routing + getConfig consumption

> Last updated: 2026-06-29
> Status: Draft

- Workstream: Embed Mode
- Backlog ID: EM-02
- Repo: `self` / `packages/webview-app` (branch `justin/wia-demo-rd1`)
- Branch: TBD
- PR: TBD

### Why

- **Demo unblock.** A first-time user (no registered document) who opens a
  verification request lands on the proof screen and fails
  (`passport_data_not_found`, `screens/embed/EmbedProvingScreen.tsx:58`). There is
  no path from the verification entry into onboarding. They must be routed into the
  scan flow and resumed to disclose after registration.
- **Root cause (verified).** The SDK launches the WebView at
  `…/tunnel/tour/1?disclosures=…` (`QueryParamsBuilder` + `BUNDLED_TOUR_PATH`). The
  web app has no matching route, so React Router drops to the catch-all `path="*"`
  → `InitialRouteRedirect` → unconditional `<Navigate to="/disclose/request">` on
  the `disclosures` param, with **no document awareness**.

### Scope — two parts, demo-critical first

**Part A — demo-critical (independent of EM-01; this is what ships the demo).**
The fix lives entirely in `webview-app` and works at the catch-all regardless of
whether `getConfig`/embed mode is active, because the catch-all is the entry the
SDK's launch URL actually hits.

1. **Doc-aware `InitialRouteRedirect`.** On a verification-request param
   (`disclosures` | `proofItems`): run an async `loadSelectedDocument(client)`
   check behind a loading state.
   - `metadata.isRegistered === true` → `/disclose/request` (preserve `search`) —
     today's behavior, unchanged.
   - not registered / unknown / error → onboarding (`/tour/1`).
     Reuse the decision already in `screens/embed/TourScreen.tsx:29-39` — extract it
     into a shared helper so it is not duplicated.
2. **Sticky request capture.** BrowserRouter wipes the URL query during onboarding
   navigation (prod `TourScreen`/capture routes navigate without `search`), so the
   request would be lost before the user reaches `/disclose/request`. Capture the
   request once at entry and hold it in memory so the post-registration resume
   still carries `disclosures`/`userId`/`scope`. In-memory is sufficient for the
   demo: the host re-supplies the URL on every WebView launch, so only _in-session_
   navigation loses it. (Durable host-driven sourcing is Part B / EM-01, not here.)
3. **Tests.** Unit-test the doc-aware decision. Keep `decideBootRoute` **pure** —
   if the decision needs document state, pass it in as a `BootInputs` field rather
   than awaiting inside the pure function. The mock `getConfig` handler already
   exists (`tests/utils/renderWithBridge.tsx:65`, defaults self-app); the task is
   **embed-mode fixtures/overrides**, not adding the handler.

**Routing home — CONFIRMED via the demo host (self-webview-sdk PR #26):** the
demo host (KMP test app, `SdkLaunchScreen.kt`) launches with a real
`VerificationRequest` (`disclosures="ofac"`) but implements **no `getConfig`**, so
mode is always self-app and `BootDecision`'s embed branch never fires. The
doc-aware decision therefore lives in the **catch-all** (`InitialRouteRedirect`) —
that is the only boot path that runs without `getConfig`, so this is not
re-fragmentation vs NAV-03, it is the active path. Still extract the decision into
the shared `resolveEmbedEntry` helper so `BootDecision` can call the _same_ helper
later for a real `getConfig` host (rn-sdk) — but for the demo, the catch-all is
where it fires.

**Part B — contract consumption (depends on EM-01; post-demo).** 4. Once EM-01 ships `getConfig` for the KMP/Swift shell, switch the embed
disclose/proving screens to read the request from the `OperatingMode` /
`VerificationRequest` context instead of the URL parser. Refactor
`parseVerificationRequestContext` (`utils/verificationRequest.ts:47`) to accept
a **structured object** (the raw `getConfig` payload) instead of
`URLSearchParams`, **preserving every derivation** (`normalizeEndpoint`,
`formatEndpointForDisplay`, `normalizeRequestType`, environment/chainID mapping,
`appName` default). Add `getConfig` to the `webview-bridge` mock for tests.
See `../SPEC.md` invariants — `targetOrigin`/`referenceId` stay URL-borne.

### Out of Scope

- SDK `getConfig` handler — EM-01 (`self-webview-sdk`).
- 3-domain scope expansion / `nfc`+`cameraMrz` provider registration in
  `self-webview-sdk` (separate SDK/Platform owner call; see `../SPEC.md`).
- `/tunnel/tour/1` ↔ web-route reconciliation — absorbed by Part A (the catch-all
  decides for any entry path), and the terminology side is already done (NAV-12).

### Files to Modify (Part A — demo)

| File                                            | Change                                                                                                                                                                                |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/components/InitialRouteRedirect.tsx`       | Make doc-aware + async with a loading state; defer to the shared embed-entry decision instead of the unconditional jump.                                                              |
| `src/utils/resolveEmbedEntry.ts` (new)          | Extract `loadSelectedDocument → isRegistered ? '/disclose/request' : '/tour/1'`; reused by `InitialRouteRedirect` and `embed/TourScreen`.                                             |
| `src/screens/embed/TourScreen.tsx`              | Replace the inline branch (`:29-39`) with the shared helper.                                                                                                                          |
| `src/providers/VerificationRequestProvider.tsx` | Sticky-capture the parsed request so it survives in-session navigation.                                                                                                               |
| `src/components/decideBootRoute.ts`             | Only if the decision routes through here — add a doc-state input field; keep the function pure. (Default: keep routing in `InitialRouteRedirect`, leave `decideBootRoute` untouched.) |
| tests                                           | Unit tests for `resolveEmbedEntry` / the doc-aware branch; `decideBootRoute` stays pure and its existing tests pass.                                                                  |

### Validation

```bash
cd packages/webview-app && pnpm test && pnpm build
```

**On-device, via the demo host (self-webview-sdk PR #26 tooling):**

- `make web-app` serves this `webview-app` (from the `selfxyz/self` checkout) on
  Vite `:5173`; `make run-android` loads it on a **physical device** (NFC/camera
  need real hardware).
- Use the test app's **"Reset Documents (force scan flow)"** button to clear the
  document catalog, then launch with the verification request:
  - no registered doc → onboarding (`/tour/1` → capture/NFC), then resume
    `/disclose/request` with the request intact.
  - registered doc → `/disclose/request` (unchanged).
- This is the acceptance test: EM-02a is the missing half that makes "Reset
  Documents → next launch starts onboarding" actually work (today the catch-all
  force-jumps to `/disclose/request` regardless of document state).

### Definition of Done (Part A = demo)

- [ ] No registered document + verification request → onboarding, then proof
      request after registration, with the request intact.
- [ ] Registered document + verification request → `/disclose/request` (unchanged).
- [ ] Normal self-app/browser navigation (catch-all entries **without** a
      `disclosures`/`proofItems` param) is unchanged — still redirects to `/`. The
      doc-aware change is scoped to catch-all entries that **carry** a
      verification-request param (the SDK launch shape). For those, the new
      behavior (no-doc → onboarding) is an **intentional** change: today they
      wrongly force-jump to `/disclose/request` regardless of document state.
- [ ] `decideBootRoute` stays pure/sync; existing tests pass; new doc-aware tests added.
- [ ] (Part B, post-demo) embed screens consume the request from context;
      `parseVerificationRequestContext` refactored to a structured input; mock
      `getConfig` added. Depends on EM-01.

### Status Log

- 2026-06-29: Drafted. Part A (doc-aware routing + sticky request) is the demo
  unblock and is independent of EM-01; Part B (getConfig consumption) depends on
  EM-01 and follows the demo.
