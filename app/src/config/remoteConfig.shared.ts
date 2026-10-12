// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

export interface FeatureFlagInfo {
  key: string;
  remoteValue?: FeatureFlagValue;
  overrideValue?: FeatureFlagValue;
  value: FeatureFlagValue;
  source: string;
  type: 'boolean' | 'string' | 'number';
}

// Shared types and constants for RemoteConfig
export type FeatureFlagValue = string | boolean | number;

export interface LocalOverride {
  [key: string]: FeatureFlagValue;
}

export interface RemoteConfigBackend {
  getValue(key: string): RemoteConfigValue;
  getAll(): Record<string, RemoteConfigValue>;
  setDefaults(defaults: Record<string, FeatureFlagValue>): Promise<void> | void;
  setConfigSettings(settings: Record<string, unknown>): Promise<void> | void;
  fetchAndActivate(): Promise<boolean>;
}

export interface RemoteConfigValue {
  asBoolean(): boolean;
  asNumber(): number;
  asString(): string;
  getSource(): string;
}

export interface StorageBackend {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export const LOCAL_OVERRIDES_KEY = 'feature_flag_overrides';

// Remotely-controllable hint shown on the e-Aadhaar PDF password screen. The
// UIDAI password format is decided by Aadhaar and may change, so this copy is
// served from Remote Config. Setting the remote value to an empty string hides
// the hint entirely.
export const AADHAAR_PDF_PASSWORD_HINT_FLAG = 'aadhaar_pdf_password_hint';
export const DEFAULT_AADHAAR_PDF_PASSWORD_HINT =
  'Password is the first 4 letters of your name in CAPITALS + your birth year, e.g. SELF2026.';

// Third-party (Didit) KYC verification path. The boolean is the global
// switch; the string is a comma-separated list of ISO 3166-1 alpha-3 document
// countries (e.g. "IND,USA") for which the path stays hidden even when the
// global switch is on. Both evaluate against the country the user picked, not
// the device locale.
export const KYC_FLOW_ENABLED_FLAG = 'kyc_flow_enabled';
export const KYC_FLOW_DISABLED_COUNTRIES_FLAG = 'kyc_flow_disabled_countries';
export const DEFAULT_KYC_FLOW_ENABLED = true;
export const DEFAULT_KYC_FLOW_DISABLED_COUNTRIES = '';

// Default feature flags - this should be defined by the consuming application
const defaultFlags: Record<string, string | boolean> = {
  [AADHAAR_PDF_PASSWORD_HINT_FLAG]: DEFAULT_AADHAAR_PDF_PASSWORD_HINT,
  [KYC_FLOW_ENABLED_FLAG]: DEFAULT_KYC_FLOW_ENABLED,
  [KYC_FLOW_DISABLED_COUNTRIES_FLAG]: DEFAULT_KYC_FLOW_DISABLED_COUNTRIES,
};

type RemoteConfigListener = () => void;
const remoteConfigListeners = new Set<RemoteConfigListener>();
let remoteConfigInitialized = false;

const notifyRemoteConfigListeners = () => {
  remoteConfigListeners.forEach(listener => {
    try {
      listener();
    } catch (error) {
      console.error('Remote config listener failed:', error);
    }
  });
};

/**
 * Runs `listener` whenever the effective flag values may have changed: after
 * the initial fetch, a manual refresh, or a local override edit. If remote
 * config is already initialized the listener runs once immediately, so late
 * subscribers never miss the first activation.
 */
export const subscribeToRemoteConfig = (
  listener: RemoteConfigListener,
): (() => void) => {
  remoteConfigListeners.add(listener);
  if (remoteConfigInitialized) {
    listener();
  }
  return () => {
    remoteConfigListeners.delete(listener);
  };
};

export const clearAllLocalOverrides = async (
  storage: StorageBackend,
): Promise<void> => {
  try {
    await storage.removeItem(LOCAL_OVERRIDES_KEY);
    notifyRemoteConfigListeners();
  } catch (error) {
    console.error('Failed to clear all local overrides:', error);
  }
};

export const clearLocalOverride = async (
  storage: StorageBackend,
  flag: string,
): Promise<void> => {
  try {
    const overrides = await getLocalOverrides(storage);
    delete overrides[flag];
    await storage.setItem(LOCAL_OVERRIDES_KEY, JSON.stringify(overrides));
    notifyRemoteConfigListeners();
  } catch (error) {
    console.error('Failed to clear local override:', error);
  }
};

export const getAllFeatureFlags = async (
  remoteConfig: RemoteConfigBackend,
  storage: StorageBackend,
): Promise<FeatureFlagInfo[]> => {
  try {
    const keys = remoteConfig.getAll();
    const localOverrides = await getLocalOverrides(storage);

    // Get all remote/default flags
    const remoteFlags = Object.keys(keys).map(key => {
      const configValue = keys[key];

      // Try to determine the type from default flags or infer from value
      const defaultValue = defaultFlags[key];
      const remoteVal =
        defaultValue !== undefined
          ? getRemoteConfigValue(remoteConfig, key, defaultValue)
          : configValue.asString(); // Default to string if no default defined

      const hasLocalOverride = Object.prototype.hasOwnProperty.call(
        localOverrides,
        key,
      );
      const overrideVal = hasLocalOverride ? localOverrides[key] : undefined;
      const effectiveVal = hasLocalOverride ? overrideVal! : remoteVal;

      // Determine type
      const type =
        typeof effectiveVal === 'boolean'
          ? 'boolean'
          : typeof effectiveVal === 'number'
            ? 'number'
            : 'string';

      return {
        key,
        remoteValue: remoteVal,
        overrideValue: overrideVal,
        value: effectiveVal,
        type: type as 'boolean' | 'string' | 'number',
        source: hasLocalOverride
          ? 'Local Override'
          : configValue.getSource() === 'remote'
            ? 'Remote Config'
            : configValue.getSource() === 'default'
              ? 'Default'
              : configValue.getSource() === 'static'
                ? 'Static'
                : 'Unknown',
      };
    });

    // Add any local overrides that don't exist in remote config
    const localOnlyFlags = Object.keys(localOverrides)
      .filter(key => !Object.prototype.hasOwnProperty.call(keys, key))
      .map(key => {
        const value = localOverrides[key];
        const type =
          typeof value === 'boolean'
            ? 'boolean'
            : typeof value === 'number'
              ? 'number'
              : 'string';

        return {
          key,
          remoteValue: undefined,
          overrideValue: value,
          value: value,
          type: type as 'boolean' | 'string' | 'number',
          source: 'Local Override',
        };
      });

    return [...remoteFlags, ...localOnlyFlags].sort((a, b) =>
      a.key.localeCompare(b.key),
    );
  } catch (error) {
    console.error('Failed to get all feature flags:', error);
    return [];
  }
};

export const getFeatureFlag = async <T extends FeatureFlagValue>(
  remoteConfig: RemoteConfigBackend,
  storage: StorageBackend,
  flag: string,
  defaultValue: T,
): Promise<T> => {
  try {
    // Check local overrides first
    const localOverrides = await getLocalOverrides(storage);
    if (Object.prototype.hasOwnProperty.call(localOverrides, flag)) {
      return localOverrides[flag] as T;
    }

    // For string flags, only override the baked-in default when the server has
    // actually set a value. An explicit empty string is a valid remote value
    // (used to hide optional UI copy), so we key off the value source rather
    // than emptiness.
    if (typeof defaultValue === 'string') {
      const configValue = remoteConfig.getValue(flag);
      if (configValue.getSource() === 'remote') {
        return configValue.asString() as T;
      }
      return defaultValue;
    }

    // Fall back to remote config for number and boolean flags
    return getRemoteConfigValue(remoteConfig, flag, defaultValue) as T;
  } catch (error) {
    console.error('Failed to get feature flag:', error);
    return defaultValue;
  }
};

// Local override management
export const getLocalOverrides = async (
  storage: StorageBackend,
): Promise<LocalOverride> => {
  try {
    const overrides = await storage.getItem(LOCAL_OVERRIDES_KEY);
    if (!overrides) {
      return {};
    }
    return JSON.parse(overrides);
  } catch (error) {
    console.error('Failed to get local overrides:', error);

    // If JSON parsing fails, clear the corrupt data
    if (error instanceof SyntaxError) {
      try {
        await storage.removeItem(LOCAL_OVERRIDES_KEY);
      } catch (removeError) {
        console.error('Failed to clear corrupt local overrides:', removeError);
      }
    }

    return {};
  }
};

// Helper function to detect and parse remote config values
export const getRemoteConfigValue = (
  remoteConfig: RemoteConfigBackend,
  key: string,
  defaultValue: FeatureFlagValue,
): FeatureFlagValue => {
  const configValue = remoteConfig.getValue(key);

  if (typeof defaultValue === 'boolean') {
    return configValue.asBoolean();
  } else if (typeof defaultValue === 'number') {
    return configValue.asNumber();
  } else if (typeof defaultValue === 'string') {
    return configValue.asString();
  }

  // Fallback: try to infer type from the remote config value
  const stringValue = configValue.asString();
  if (stringValue === 'true' || stringValue === 'false') {
    return configValue.asBoolean();
  }
  if (!Number.isNaN(Number(stringValue)) && stringValue !== '') {
    return configValue.asNumber();
  }
  return stringValue;
};

export const initRemoteConfig = async (
  remoteConfig: RemoteConfigBackend,
): Promise<void> => {
  await remoteConfig.setDefaults(defaultFlags);
  await remoteConfig.setConfigSettings({
    minimumFetchIntervalMillis: __DEV__ ? 0 : 3600000,
  });
  try {
    await remoteConfig.fetchAndActivate();
  } catch (err) {
    console.error('Remote config fetch failed', err);
  }
  remoteConfigInitialized = true;
  notifyRemoteConfigListeners();
};

export const refreshRemoteConfig = async (
  remoteConfig: RemoteConfigBackend,
): Promise<void> => {
  try {
    await remoteConfig.fetchAndActivate();
  } catch (err) {
    console.error('Remote config refresh failed', err);
  }
  notifyRemoteConfigListeners();
};

export const setLocalOverride = async (
  storage: StorageBackend,
  flag: string,
  value: FeatureFlagValue,
): Promise<void> => {
  try {
    const overrides = await getLocalOverrides(storage);
    overrides[flag] = value;
    await storage.setItem(LOCAL_OVERRIDES_KEY, JSON.stringify(overrides));
    notifyRemoteConfigListeners();
  } catch (error) {
    console.error('Failed to set local override:', error);
  }
};
