// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// Copies the built WebView bundle (../webview-app/dist) into ./assets/self-wallet
// so it can be embedded and loaded over file://. Two behaviors matter here:
//
//  1. Source maps are always excluded. The .js.map files add ~21MB to the
//     shipped package but are never used at runtime on device; dropping them
//     roughly halves the embedded bundle size.
//  2. SELF_SKIP_WALLET_BUNDLE=1 skips the copy entirely. Production builds that
//     do not embed the wallet (bundle served/loaded elsewhere) can avoid paying
//     the copy cost. When skipping we also remove any stale prior bundle so it
//     cannot leak into a build that is supposed to ship without one.
const fs = require('node:fs');
const path = require('node:path');

const src = path.join(__dirname, '../../webview-app/dist');
const dst = path.join(__dirname, '../assets/self-wallet');

if (process.env.SELF_SKIP_WALLET_BUNDLE === '1') {
  // Remove any bundle left over from a prior build; do NOT copy or strip SRI.
  fs.rmSync(dst, { recursive: true, force: true });
  console.log(
    'copy-embedded-bundle: skipping embedded webview bundle (SELF_SKIP_WALLET_BUNDLE=1)',
  );
  process.exit(0);
}

if (!fs.existsSync(src)) {
  console.error(
    `copy-embedded-bundle: ${src} not found; build @selfxyz/webview-app first`,
  );
  process.exit(1);
}

fs.rmSync(dst, { recursive: true, force: true });
fs.mkdirSync(dst, { recursive: true });
// Exclude source maps: dead weight on device, ~21MB of .js.map.
fs.cpSync(src, dst, { recursive: true, filter: (p) => !p.endsWith('.map') });
console.log(`copy-embedded-bundle: copied ${src} -> ${dst} (source maps excluded)`);

// Strip SRI from the embedded index.html so the file:// bundle boots on iOS.
// strip-embedded-sri.cjs runs its logic as a top-level side-effect on require.
require('./strip-embedded-sri.cjs');
