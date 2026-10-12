#!/usr/bin/env node

// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

/**
 * Centralized Version Manager for Mobile Deployments
 *
 * Single source of truth for all version operations across:
 * - GitHub Actions workflows
 * - Fastlane (read-only consumption)
 * - Local development
 *
 * Version Bump Behavior (Option B - Continue build numbers):
 * - major: 2.6.9 → 3.0.0, increment build numbers
 * - minor: 2.6.9 → 2.7.0, increment build numbers
 * - patch: 2.6.9 → 2.6.10, increment build numbers
 * - build: 2.6.9 → 2.6.9, increment build numbers only
 *
 * Platform-specific logic:
 * - ios: Only increment iOS build number
 * - android: Only increment Android build number
 * - both/undefined: Increment both build numbers
 */

const fs = require('fs');
const path = require('path');

const APP_DIR = path.resolve(__dirname, '..');
const VERSION_MANAGED_RELATIVE_PATHS = [
  'package.json',
  'version.json',
  path.join('android', 'app', 'build.gradle'),
  path.join('ios', 'Self.xcodeproj', 'project.pbxproj'),
];
const [
  PACKAGE_JSON_REL_PATH,
  VERSION_JSON_REL_PATH,
  ANDROID_GRADLE_REL_PATH,
  IOS_PBXPROJ_REL_PATH,
] = VERSION_MANAGED_RELATIVE_PATHS;
const PACKAGE_JSON_PATH = path.join(APP_DIR, PACKAGE_JSON_REL_PATH);
const VERSION_JSON_PATH = path.join(APP_DIR, VERSION_JSON_REL_PATH);
const ANDROID_GRADLE_PATH = path.join(APP_DIR, ANDROID_GRADLE_REL_PATH);
const IOS_PBXPROJ_PATH = path.join(APP_DIR, IOS_PBXPROJ_REL_PATH);

/**
 * Get the list of files managed by applyVersions()
 */
function getVersionManagedFiles() {
  return [...VERSION_MANAGED_RELATIVE_PATHS];
}

/**
 * Read package.json
 */
function readPackageJson() {
  if (!fs.existsSync(PACKAGE_JSON_PATH)) {
    throw new Error(`package.json not found at ${PACKAGE_JSON_PATH}`);
  }

  try {
    return JSON.parse(fs.readFileSync(PACKAGE_JSON_PATH, 'utf8'));
  } catch (error) {
    throw new Error(`Failed to parse package.json: ${error.message}`);
  }
}

/**
 * Read version.json
 */
function readVersionJson() {
  if (!fs.existsSync(VERSION_JSON_PATH)) {
    throw new Error(`version.json not found at ${VERSION_JSON_PATH}`);
  }

  try {
    return JSON.parse(fs.readFileSync(VERSION_JSON_PATH, 'utf8'));
  } catch (error) {
    throw new Error(`Failed to parse version.json: ${error.message}`);
  }
}

/**
 * Write package.json
 */
function writePackageJson(data) {
  try {
    fs.writeFileSync(PACKAGE_JSON_PATH, JSON.stringify(data, null, 2) + '\n');
  } catch (error) {
    throw new Error(`Failed to write package.json: ${error.message}`);
  }
}

/**
 * Write version.json
 */
function writeVersionJson(data) {
  try {
    fs.writeFileSync(VERSION_JSON_PATH, JSON.stringify(data, null, 2) + '\n');
  } catch (error) {
    throw new Error(`Failed to write version.json: ${error.message}`);
  }
}

/**
 * Update a file with a regex replacement, ensuring at least one match.
 */
function updateFileWithRegex(filePath, regex, replacement) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found at ${filePath}`);
  }

  const contents = fs.readFileSync(filePath, 'utf8');
  const matches = contents.match(regex);

  if (!matches) {
    throw new Error(`No matches for ${regex} in ${filePath}`);
  }

  const updated = contents.replace(regex, replacement);

  if (updated !== contents) {
    fs.writeFileSync(filePath, updated);
  }

  return matches.length;
}

/**
 * Get current version information
 */
function getVersionInfo() {
  const pkg = readPackageJson();
  const versionData = readVersionJson();

  return {
    version: pkg.version,
    iosBuild: versionData.ios.build,
    androidBuild: versionData.android.build,
    iosLastDeployed: versionData.ios.lastDeployed,
    androidLastDeployed: versionData.android.lastDeployed,
  };
}

/**
 * Bump semantic version (major/minor/patch)
 */
function bumpSemanticVersion(currentVersion, bumpType) {
  const parts = currentVersion.split('.').map(Number);

  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error(
      `Invalid version format: ${currentVersion}. Expected X.Y.Z`,
    );
  }

  let [major, minor, patch] = parts;

  switch (bumpType) {
    case 'major':
      major += 1;
      minor = 0;
      patch = 0;
      break;
    case 'minor':
      minor += 1;
      patch = 0;
      break;
    case 'patch':
      patch += 1;
      break;
    default:
      throw new Error(
        `Invalid bump type: ${bumpType}. Expected major, minor, or patch`,
      );
  }

  return `${major}.${minor}.${patch}`;
}

/**
 * Bump version and build numbers
 *
 * @param {string} bumpType - 'major', 'minor', 'patch', or 'build'
 * @param {string} platform - 'ios', 'android', or 'both' (default)
 * @returns {object} - New version info
 */
function bumpVersion(bumpType, platform = 'both') {
  const validBumpTypes = ['major', 'minor', 'patch', 'build'];
  const validPlatforms = ['ios', 'android', 'both'];

  if (!validBumpTypes.includes(bumpType)) {
    throw new Error(
      `Invalid bump type: ${bumpType}. Expected: ${validBumpTypes.join(', ')}`,
    );
  }

  if (!validPlatforms.includes(platform)) {
    throw new Error(
      `Invalid platform: ${platform}. Expected: ${validPlatforms.join(', ')}`,
    );
  }

  const pkg = readPackageJson();
  const versionData = readVersionJson();

  let newVersion = pkg.version;

  // Bump semantic version if major/minor/patch
  if (bumpType !== 'build') {
    newVersion = bumpSemanticVersion(pkg.version, bumpType);
    console.log(
      `📦 Bumping ${bumpType} version: ${pkg.version} → ${newVersion}`,
    );
  } else {
    console.log(`📦 Keeping version: ${newVersion} (build-only bump)`);
  }

  // Bump build numbers based on platform
  let newIosBuild = versionData.ios.build;
  let newAndroidBuild = versionData.android.build;

  if (platform === 'ios' || platform === 'both') {
    newIosBuild += 1;
    console.log(`🍎 iOS build: ${versionData.ios.build} → ${newIosBuild}`);
  } else {
    console.log(`🍎 iOS build: ${newIosBuild} (unchanged)`);
  }

  if (platform === 'android' || platform === 'both') {
    newAndroidBuild += 1;
    console.log(
      `🤖 Android build: ${versionData.android.build} → ${newAndroidBuild}`,
    );
  } else {
    console.log(`🤖 Android build: ${newAndroidBuild} (unchanged)`);
  }

  return {
    version: newVersion,
    iosBuild: newIosBuild,
    androidBuild: newAndroidBuild,
  };
}

/**
 * Apply version changes to files
 *
 * @param {string} version - Semantic version (X.Y.Z)
 * @param {number|string} iosBuild - iOS build number
 * @param {number|string} androidBuild - Android build number
 * @param {object} [options] - Optional settings
 * @param {boolean} [options.iosSuccess=true] - Whether the iOS build succeeded
 * @param {boolean} [options.androidSuccess=true] - Whether the Android build succeeded
 */
function applyVersions(
  version,
  iosBuild,
  androidBuild,
  { iosSuccess = true, androidSuccess = true } = {},
) {
  // Validate version format (semver X.Y.Z)
  if (
    !version ||
    typeof version !== 'string' ||
    !/^\d+\.\d+\.\d+$/.test(version)
  ) {
    throw new Error(`Invalid version format: ${version}. Expected X.Y.Z`);
  }

  // Validate and coerce build numbers
  const iosNum = Number(iosBuild);
  const androidNum = Number(androidBuild);

  if (!Number.isInteger(iosNum) || iosNum < 1) {
    throw new Error(`Invalid iOS build: ${iosBuild}. Must be positive integer`);
  }

  if (!Number.isInteger(androidNum) || androidNum < 1) {
    throw new Error(
      `Invalid Android build: ${androidBuild}. Must be positive integer`,
    );
  }

  console.log(`📝 Applying versions to files...`);
  console.log(`   Version: ${version}`);
  console.log(
    `   iOS Build: ${iosNum} (${iosSuccess ? 'succeeded' : 'skipped'})`,
  );
  console.log(
    `   Android Build: ${androidNum} (${androidSuccess ? 'succeeded' : 'skipped'})`,
  );

  // Update package.json
  const pkg = readPackageJson();
  pkg.version = version;
  writePackageJson(pkg);
  console.log(`✅ Updated package.json`);

  // Update version.json (conditionally per platform)
  const versionData = readVersionJson();
  const timestamp = new Date().toISOString();

  if (iosSuccess) {
    versionData.ios.build = iosNum;
    versionData.ios.lastDeployed = timestamp;
    console.log(
      `✅ Updated iOS build number to ${iosNum} and lastDeployed timestamp`,
    );
  } else {
    console.log(`⏭️  Skipped iOS version.json update (build did not succeed)`);
  }

  if (androidSuccess) {
    versionData.android.build = androidNum;
    versionData.android.lastDeployed = timestamp;
    console.log(
      `✅ Updated Android build number to ${androidNum} and lastDeployed timestamp`,
    );
  } else {
    console.log(
      `⏭️  Skipped Android version.json update (build did not succeed)`,
    );
  }

  writeVersionJson(versionData);

  // Update Android build.gradle versionCode
  if (androidSuccess) {
    const androidMatches = updateFileWithRegex(
      ANDROID_GRADLE_PATH,
      /versionCode\s+\d+/g,
      `versionCode ${androidNum}`,
    );
    console.log(
      `✅ Updated Android versionCode (${androidMatches} occurrence${
        androidMatches === 1 ? '' : 's'
      })`,
    );
  } else {
    console.log(
      `⏭️  Skipped Android build.gradle update (build did not succeed)`,
    );
  }

  // Update iOS project version and marketing version
  if (iosSuccess) {
    const iosBuildMatches = updateFileWithRegex(
      IOS_PBXPROJ_PATH,
      /CURRENT_PROJECT_VERSION = \d+;/g,
      `CURRENT_PROJECT_VERSION = ${iosNum};`,
    );
    console.log(
      `✅ Updated iOS CURRENT_PROJECT_VERSION (${iosBuildMatches} occurrence${
        iosBuildMatches === 1 ? '' : 's'
      })`,
    );
  } else {
    console.log(
      `⏭️  Skipped iOS CURRENT_PROJECT_VERSION update (build did not succeed)`,
    );
  }

  // Always update MARKETING_VERSION to keep it in sync with package.json
  const iosMarketingMatches = updateFileWithRegex(
    IOS_PBXPROJ_PATH,
    /MARKETING_VERSION = \d+\.\d+\.\d+;/g,
    `MARKETING_VERSION = ${version};`,
  );
  console.log(
    `✅ Updated iOS MARKETING_VERSION (${iosMarketingMatches} occurrence${
      iosMarketingMatches === 1 ? '' : 's'
    })`,
  );

  // Android has no MARKETING_VERSION equivalent: versionName is a literal in
  // build.gradle, so it must be rewritten here or the binary keeps the old
  // marketing version. Info.plist reads $(MARKETING_VERSION), so iOS is covered.
  const androidVersionNameMatches = updateFileWithRegex(
    ANDROID_GRADLE_PATH,
    /versionName\s+"\d+\.\d+\.\d+"/g,
    `versionName "${version}"`,
  );
  console.log(
    `✅ Updated Android versionName (${androidVersionNameMatches} occurrence${
      androidVersionNameMatches === 1 ? '' : 's'
    })`,
  );
}

/**
 * CLI Interface
 */
function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  try {
    switch (command) {
      case 'get': {
        // Get current version info
        const info = getVersionInfo();
        console.log(JSON.stringify(info, null, 2));

        // Also output for GitHub Actions
        if (process.env.GITHUB_OUTPUT) {
          const output = [
            `version=${info.version}`,
            `ios_build=${info.iosBuild}`,
            `android_build=${info.androidBuild}`,
          ].join('\n');
          fs.appendFileSync(process.env.GITHUB_OUTPUT, output + '\n');
        }
        break;
      }

      case 'bump': {
        // Bump version: bump <type> <platform>
        const bumpType = args[1] || 'build';
        const platform = args[2] || 'both';

        const result = bumpVersion(bumpType, platform);
        console.log(`\n✅ Version bump calculated:`);
        console.log(JSON.stringify(result, null, 2));

        // Output for GitHub Actions
        if (process.env.GITHUB_OUTPUT) {
          const output = [
            `version=${result.version}`,
            `ios_build=${result.iosBuild}`,
            `android_build=${result.androidBuild}`,
          ].join('\n');
          fs.appendFileSync(process.env.GITHUB_OUTPUT, output + '\n');
        }

        break;
      }

      case 'apply': {
        // Apply version: apply <version> <iosBuild> <androidBuild> [iosResult] [androidResult]
        const version = args[1];
        const iosBuild = parseInt(args[2], 10);
        const androidBuild = parseInt(args[3], 10);

        if (!version || isNaN(iosBuild) || isNaN(androidBuild)) {
          throw new Error(
            'Usage: apply <version> <iosBuild> <androidBuild> [iosResult] [androidResult]',
          );
        }

        // Optional platform result args: "success" means succeeded, anything else means skipped
        const iosSuccess = args[4] ? args[4] === 'success' : true;
        const androidSuccess = args[5] ? args[5] === 'success' : true;

        applyVersions(version, iosBuild, androidBuild, {
          iosSuccess,
          androidSuccess,
        });
        console.log(`\n✅ Versions applied successfully`);
        break;
      }

      case 'files': {
        // List files managed by applyVersions()
        const format = args[1];

        if (format && !['--shell', '--json'].includes(format)) {
          throw new Error('Usage: files [--shell|--json]');
        }

        const files = getVersionManagedFiles();

        if (format === '--shell') {
          console.log(files.join(' '));
        } else if (format === '--json') {
          console.log(JSON.stringify(files));
        } else {
          console.log(files.join('\n'));
        }

        if (process.env.GITHUB_OUTPUT) {
          fs.appendFileSync(
            process.env.GITHUB_OUTPUT,
            `version_managed_files=${files.join(' ')}\n`,
          );
        }

        break;
      }

      default:
        console.log(`
Mobile Version Manager

Usage:
  node version-manager.cjs <command> [options]

Commands:
  get                           Get current version information
  bump <type> <platform>        Bump version and calculate new build numbers
                                type: major|minor|patch|build (default: build)
                                platform: ios|android|both (default: both)
  apply <version> <ios> <android> [iosResult] [androidResult]
                                  Apply specific version and build numbers
                                  iosResult/androidResult: "success" to update,
                                  any other value to skip (default: "success")
  files [--shell|--json]        List files managed by applyVersions()
                                default output: one path per line
                                --shell: space-separated paths
                                --json: JSON array

Examples:
  node version-manager.cjs get
  node version-manager.cjs bump build both
  node version-manager.cjs bump patch ios
  node version-manager.cjs apply 2.7.0 180 109
  node version-manager.cjs apply 2.7.0 180 109 success failure
  node version-manager.cjs files --shell
        `);
        process.exit(command ? 1 : 0);
    }
  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
    process.exit(1);
  }
}

// Run CLI if called directly
if (require.main === module) {
  main();
}

// Export functions for use as module
module.exports = {
  applyVersions,
  bumpVersion,
  getVersionManagedFiles,
  getVersionInfo,
  readPackageJson,
  readVersionJson,
};
