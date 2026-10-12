// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { create } from 'zustand';

import { getFeatureFlag, subscribeToRemoteConfig } from '@/config/remoteConfig';
import {
  DEFAULT_KYC_FLOW_DISABLED_COUNTRIES,
  DEFAULT_KYC_FLOW_ENABLED,
  KYC_FLOW_DISABLED_COUNTRIES_FLAG,
  KYC_FLOW_ENABLED_FLAG,
} from '@/config/remoteConfig.shared';

interface KycAvailabilityState {
  enabled: boolean;
  disabledCountries: readonly string[];
  hydrated: boolean;
}

export const parseDisabledCountries = (raw: string): string[] =>
  raw
    .split(',')
    .map(code => code.trim().toUpperCase())
    .filter(code => code.length > 0);

export const useKycAvailabilityStore = create<KycAvailabilityState>(() => ({
  enabled: DEFAULT_KYC_FLOW_ENABLED,
  disabledCountries: parseDisabledCountries(
    DEFAULT_KYC_FLOW_DISABLED_COUNTRIES,
  ),
  hydrated: false,
}));

const evaluate = (
  { enabled, disabledCountries }: KycAvailabilityState,
  countryCode?: string,
): boolean => {
  if (!enabled) {
    return false;
  }
  const normalized = countryCode?.trim().toUpperCase();
  if (!normalized) {
    return true;
  }
  return !disabledCountries.includes(normalized);
};

/**
 * Re-reads the KYC flags from remote config (local overrides win) into the
 * store so the synchronous gates below reflect the latest activation.
 */
export const syncKycAvailability = async (): Promise<void> => {
  try {
    const [enabled, disabledCountriesRaw] = await Promise.all([
      getFeatureFlag(KYC_FLOW_ENABLED_FLAG, DEFAULT_KYC_FLOW_ENABLED),
      getFeatureFlag(
        KYC_FLOW_DISABLED_COUNTRIES_FLAG,
        DEFAULT_KYC_FLOW_DISABLED_COUNTRIES,
      ),
    ]);
    useKycAvailabilityStore.setState({
      enabled,
      disabledCountries: parseDisabledCountries(disabledCountriesRaw),
      hydrated: true,
    });
  } catch (error) {
    console.error('Failed to sync KYC availability flags:', error);
  }
};

subscribeToRemoteConfig(() => {
  syncKycAvailability();
});

/**
 * Whether the third-party (Didit) verification path may be offered. Pass the
 * ISO 3166-1 alpha-3 code of the document country when one is known; without
 * it only the global switch applies. Reads the last synced values, so it is
 * safe outside React (navigation listeners, notification handlers).
 */
export const isKycFlowEnabled = (countryCode?: string): boolean =>
  evaluate(useKycAvailabilityStore.getState(), countryCode);

/** Reactive variant of `isKycFlowEnabled` for render paths. */
export const useKycFlowEnabled = (countryCode?: string): boolean =>
  useKycAvailabilityStore(state => evaluate(state, countryCode));
