// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

/**
 * Barrel export file for configuration.
 * Re-exports shared config and platform-specific configs.
 * Platform-specific files (.ts vs .web.ts) are resolved automatically by TypeScript.
 */

// Remote config - shared types and utilities
export type {
  FeatureFlagInfo,
  FeatureFlagValue,
  LocalOverride,
  RemoteConfigBackend,
  RemoteConfigValue,
  StorageBackend,
} from '@/config/remoteConfig.shared';
export {
  AADHAAR_PDF_PASSWORD_HINT_FLAG,
  DEFAULT_AADHAAR_PDF_PASSWORD_HINT,
  LOCAL_OVERRIDES_KEY,
} from '@/config/remoteConfig.shared';

// Sentry error tracking
// Platform-specific files (.ts vs .web.ts) are resolved automatically
export {
  captureException,
  captureFeedback,
  captureMessage,
  initSentry,
  isSentryDisabled,
  logAuthEvent,
  logEvent,
  logNFCEvent,
  logProofEvent,
  setSupportUuidInSentry,
  wrapWithSentry,
} from '@/config/sentry';

// Remote config - platform-specific implementations
// TypeScript will automatically resolve .ts vs .web.ts based on platform
export {
  clearAllLocalOverrides,
  clearLocalOverride,
  getAllFeatureFlags,
  getFeatureFlag,
  getLocalOverrides,
  initRemoteConfig,
  readFeatureFlag,
  refreshRemoteConfig,
  setLocalOverride,
  subscribeToRemoteConfig,
} from '@/config/remoteConfig';

// Segment analytics
export { createSegmentClient } from '@/config/segment';
