#!/usr/bin/env node
// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

/**
 * npm postinstall: fetch the prebuilt iOS NFC binaries into ios/Frameworks/.
 *
 * The passport reader ships as prebuilt binary xcframeworks (RN-08 policy): they are large,
 * private, and must not live in the npm tarball. CocoaPods reads whatever this script places in
 * ios/Frameworks/ via the podspec's conditional `vendored_frameworks`. When the binaries are
 * absent the Swift module compiles in its `#if canImport(SelfSdkNfc)` stub branch, so
 * `pod install` never hard-fails on a missing private artifact.
 *
 * Source: GitHub Release assets on the PRIVATE distribution repo selfxyz/self-sdk-dist. Private
 * release assets are only served through the API asset URL with `Accept: application/octet-stream`
 * (the browser_download_url 404s), so a token with read access is required.
 *
 * Environment:
 *   SELF_SDK_GITHUB_TOKEN / GITHUB_TOKEN / GH_TOKEN
 *                              GitHub token with read access to selfxyz/self-sdk-dist (first set
 *                              wins). Absent → skip gracefully (exit 0) so OSS/CI installs without
 *                              access don't hard-fail; the podspec stubs when frameworks are absent.
 *   SELF_SDK_DIST_VERSION      Override the artifact version used in asset names / the default tag
 *                              (default: this package's version). The published assets are named
 *                              SelfSdkNfc-<version>.xcframework.zip etc.
 *   SELF_SDK_DIST_TAG          Override the full release tag (default: `rn-v<version>`).
 *   SELF_SDK_FRAMEWORKS_URL    Override base URL (https://… or file:///…) of a directory holding
 *                              the <name>-<version>.xcframework.zip (+ .sha256). No token needed;
 *                              used to validate against locally built zips before a Release exists.
 *   SELF_SDK_SKIP_IOS_DOWNLOAD Set to 1 to skip entirely (Android-only installs).
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync, execSync } = require('child_process');

const PACKAGE_ROOT = path.resolve(__dirname, '..');
const FRAMEWORKS_DIR = path.join(PACKAGE_ROOT, 'ios', 'Frameworks');
const DIST_REPO = 'selfxyz/self-sdk-dist';

// The passport reader xcframeworks vendored by selfxyz-rn-nfc-passport.podspec. Mixpanel is pulled
// transitively by the NFCPassportReader fork; its zip also carries Mixpanel_Mixpanel.bundle, which
// is extracted alongside and picked up by the podspec's `s.resources`.
const ARTIFACTS = ['SelfSdkNfc', 'SelfNFCPassportReader', 'Mixpanel'];

const log = (msg) => console.log(`[@selfxyz/rn-nfc-passport] ${msg}`);
const warn = (msg) => console.warn(`[@selfxyz/rn-nfc-passport] ${msg}`);

function getToken() {
  return (
    process.env.SELF_SDK_GITHUB_TOKEN || process.env.GITHUB_TOKEN || process.env.GH_TOKEN || ''
  );
}

// Returns a string reason to skip, or null to proceed.
function shouldSkip() {
  if (process.env.SELF_SDK_SKIP_IOS_DOWNLOAD === '1') {
    return 'SELF_SDK_SKIP_IOS_DOWNLOAD=1';
  }
  if (process.platform !== 'darwin') {
    return `platform is ${process.platform} (iOS binaries are only usable on macOS)`;
  }
  const missing = ARTIFACTS.filter(
    (name) => !fs.existsSync(path.join(FRAMEWORKS_DIR, `${name}.xcframework`))
  );
  if (missing.length === 0) {
    return 'frameworks already present';
  }
  return null;
}

async function fetchBuffer(url, headers) {
  if (url.startsWith('file://')) {
    return fs.readFileSync(new URL(url));
  }
  const res = await fetch(url, { headers, redirect: 'follow' });
  if (!res.ok) {
    const err = new Error(`GET ${url} → HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return Buffer.from(await res.arrayBuffer());
}

// Resolve { zip, sha256 } buffers for one artifact, from the override dir or the private Release.
async function download(name, version, tag, release) {
  const zipName = `${name}-${version}.xcframework.zip`;

  const baseUrl = process.env.SELF_SDK_FRAMEWORKS_URL;
  if (baseUrl) {
    log(`fetching ${zipName} from override URL ${baseUrl}`);
    const base = baseUrl.replace(/\/$/, '');
    return {
      zip: await fetchBuffer(`${base}/${zipName}`),
      sha256: await fetchBuffer(`${base}/${zipName}.sha256`),
    };
  }

  const token = getToken();
  const apiHeaders = {
    authorization: `Bearer ${token}`,
    'user-agent': 'selfxyz-rn-nfc-passport-postinstall',
  };
  const assetIdFor = (assetName) => {
    const asset = (release.assets || []).find((a) => a.name === assetName);
    if (!asset) {
      throw new Error(`release ${tag} on ${DIST_REPO} has no asset '${assetName}'`);
    }
    // API asset URL; the octet-stream Accept turns it into the binary.
    return `https://api.github.com/repos/${DIST_REPO}/releases/assets/${asset.id}`;
  };
  const binHeaders = { ...apiHeaders, accept: 'application/octet-stream' };
  log(`downloading ${zipName} from ${DIST_REPO} release ${tag}`);
  return {
    zip: await fetchBuffer(assetIdFor(zipName), binHeaders),
    sha256: await fetchBuffer(assetIdFor(`${zipName}.sha256`), binHeaders),
  };
}

// Locate an unzip tool. `ditto` (macOS) preserves the .xcframework / .bundle structure best;
// `unzip` is the portable fallback.
function resolveUnzip() {
  for (const [cmd, args] of [
    ['ditto', (zip, dst) => ['-x', '-k', zip, dst]],
    ['unzip', (zip, dst) => ['-o', '-q', zip, '-d', dst]],
  ]) {
    try {
      execSync(`command -v ${cmd}`, { stdio: 'ignore' });
      return { cmd, buildArgs: args };
    } catch {
      /* not available; try next */
    }
  }
  return null;
}

function verifyAndExtract(name, version, zip, sha256, unzip) {
  const expected = sha256.toString().trim().split(/\s+/)[0];
  const actual = crypto.createHash('sha256').update(zip).digest('hex');
  if (expected !== actual) {
    throw new Error(
      `${name}-${version}.xcframework.zip sha256 mismatch: ${actual} != ${expected}`
    );
  }
  fs.mkdirSync(FRAMEWORKS_DIR, { recursive: true });
  const zipPath = path.join(FRAMEWORKS_DIR, `${name}-${version}.xcframework.zip`);
  fs.writeFileSync(zipPath, zip);
  try {
    execFileSync(unzip.cmd, unzip.buildArgs(zipPath, FRAMEWORKS_DIR), { stdio: 'inherit' });
  } finally {
    fs.rmSync(zipPath, { force: true });
  }
  if (!fs.existsSync(path.join(FRAMEWORKS_DIR, `${name}.xcframework`))) {
    throw new Error(
      `${name}.xcframework missing after extracting ${name}-${version}.xcframework.zip`
    );
  }
  patchSwiftInterfaces(name);
  log(`installed ios/Frameworks/${name}.xcframework`);
}

// The dist interfaces were emitted without -module-interface-preserve-types-as-written, so
// decls are qualified as `Mixpanel.X`. Inside any interface that can see the top-level
// `Mixpanel` class, that qualifier resolves to the class instead of the module ("'X' is not a
// member type of class 'Mixpanel.Mixpanel'") and the interface fails to compile — which makes
// `#if canImport(SelfSdkNfc)` silently false and stubs the reader out even with the binaries
// present. Every `Mixpanel.`-qualified name in these interfaces is a top-level type of the
// Mixpanel module, so stripping the qualifier is safe and resolves identically.
function patchSwiftInterfaces(name) {
  const fwDir = path.join(FRAMEWORKS_DIR, `${name}.xcframework`);
  const stack = [fwDir];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const entryPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(entryPath);
      } else if (entry.name.endsWith('.swiftinterface')) {
        const text = fs.readFileSync(entryPath, 'utf8');
        const patched = text.replace(/Mixpanel\.([A-Z])/g, '$1');
        if (patched !== text) {
          fs.writeFileSync(entryPath, patched);
          log(`patched Mixpanel module-qualification in ${path.relative(PACKAGE_ROOT, entryPath)}`);
        }
      }
    }
  }
}

async function main() {
  const skip = shouldSkip();
  if (skip) {
    log(`skipping iOS binaries: ${skip}`);
    return;
  }

  const usingOverride = Boolean(process.env.SELF_SDK_FRAMEWORKS_URL);
  const token = getToken();
  if (!usingOverride && !token) {
    warn(
      'no GitHub token found (set SELF_SDK_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN with read ' +
        `access to ${DIST_REPO}) — skipping iOS NFC binary download. iOS will compile the ` +
        'unavailable stub and NFC will report not available. (Android-only setups can ignore this.)'
    );
    return;
  }

  // The iOS xcframeworks are versioned with the native self-sdk-native release (self-sdk-dist
  // rn-v* tag), NOT this shim's npm version. Keep in lockstep with the AAR pin in
  // android/build.gradle (selfNfcAarVersion); override via SELF_SDK_DIST_VERSION.
  const NATIVE_ARTIFACT_VERSION = '0.1.3';
  const version = process.env.SELF_SDK_DIST_VERSION || NATIVE_ARTIFACT_VERSION;
  const tag = process.env.SELF_SDK_DIST_TAG || `rn-v${version}`;

  const unzip = resolveUnzip();
  if (!unzip) {
    warn('neither `ditto` nor `unzip` is available — cannot extract iOS frameworks; skipping.');
    return;
  }

  // Resolve the release once (asset ids), unless using a plain-URL override.
  let release = null;
  if (!usingOverride) {
    const apiHeaders = {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'user-agent': 'selfxyz-rn-nfc-passport-postinstall',
    };
    const releaseUrl = `https://api.github.com/repos/${DIST_REPO}/releases/tags/${tag}`;
    try {
      release = JSON.parse((await fetchBuffer(releaseUrl, apiHeaders)).toString());
    } catch (err) {
      if (err.status === 404) {
        warn(
          `release ${tag} not found on ${DIST_REPO} (or the token lacks access) — skipping iOS ` +
            'NFC binary download; iOS will compile the unavailable stub.'
        );
        return;
      }
      if (err.status === 401 || err.status === 403) {
        warn(
          `not authorized to read ${DIST_REPO} (HTTP ${err.status}) — skipping iOS NFC binary ` +
            'download; iOS will compile the unavailable stub.'
        );
        return;
      }
      throw err;
    }
  }

  for (const name of ARTIFACTS) {
    if (fs.existsSync(path.join(FRAMEWORKS_DIR, `${name}.xcframework`))) {
      continue; // idempotent: already installed
    }
    const { zip, sha256 } = await download(name, version, tag, release);
    verifyAndExtract(name, version, zip, sha256, unzip);
  }
}

main().catch((err) => {
  // Fail closed on integrity problems (sha mismatch, missing asset after a release was found):
  // a corrupt/partial binary is worse than a stubbed build. Auth/availability gaps already
  // returned gracefully above.
  console.error(`[@selfxyz/rn-nfc-passport] postinstall failed: ${err.message}`);
  process.exit(1);
});
