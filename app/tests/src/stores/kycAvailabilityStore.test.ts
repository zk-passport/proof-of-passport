// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { act, renderHook, waitFor } from '@testing-library/react-native';

import { getFeatureFlag, subscribeToRemoteConfig } from '@/config/remoteConfig';
import {
  KYC_FLOW_DISABLED_COUNTRIES_FLAG,
  KYC_FLOW_ENABLED_FLAG,
} from '@/config/remoteConfig.shared';
import {
  isKycFlowEnabled,
  parseDisabledCountries,
  syncKycAvailability,
  useKycAvailabilityStore,
  useKycFlowEnabled,
} from '@/stores/kycAvailabilityStore';

jest.mock('@/config/remoteConfig', () => ({
  getFeatureFlag: jest.fn(),
  subscribeToRemoteConfig: jest.fn(() => jest.fn()),
}));

const mockGetFeatureFlag = getFeatureFlag as jest.MockedFunction<
  typeof getFeatureFlag
>;
const mockSubscribe = subscribeToRemoteConfig as jest.MockedFunction<
  typeof subscribeToRemoteConfig
>;

const setFlags = (enabled: boolean, disabledCountries: string) => {
  mockGetFeatureFlag.mockImplementation(
    async (flag: string, defaultValue: unknown) => {
      if (flag === KYC_FLOW_ENABLED_FLAG) return enabled as never;
      if (flag === KYC_FLOW_DISABLED_COUNTRIES_FLAG)
        return disabledCountries as never;
      return defaultValue as never;
    },
  );
};

describe('kycAvailabilityStore', () => {
  beforeEach(() => {
    useKycAvailabilityStore.setState({
      enabled: true,
      disabledCountries: [],
      hydrated: false,
    });
    mockGetFeatureFlag.mockReset();
  });

  it('subscribes to remote config changes on load', () => {
    expect(mockSubscribe).toHaveBeenCalledTimes(1);
  });

  it('defaults to enabled for every country before hydration', () => {
    expect(isKycFlowEnabled()).toBe(true);
    expect(isKycFlowEnabled('IND')).toBe(true);
  });

  it('parses the disabled-country list leniently', () => {
    expect(parseDisabledCountries(' ind, USA ,,fra ')).toEqual([
      'IND',
      'USA',
      'FRA',
    ]);
    expect(parseDisabledCountries('')).toEqual([]);
  });

  it('hydrates from the remote flags', async () => {
    setFlags(true, 'IND,USA');

    await syncKycAvailability();

    expect(useKycAvailabilityStore.getState()).toEqual({
      enabled: true,
      disabledCountries: ['IND', 'USA'],
      hydrated: true,
    });
  });

  it('hides the flow only for listed countries when globally enabled', async () => {
    setFlags(true, 'IND');
    await syncKycAvailability();

    expect(isKycFlowEnabled()).toBe(true);
    expect(isKycFlowEnabled('FRA')).toBe(true);
    expect(isKycFlowEnabled('IND')).toBe(false);
    expect(isKycFlowEnabled('ind')).toBe(false);
  });

  it('hides the flow everywhere when the global switch is off', async () => {
    setFlags(false, '');
    await syncKycAvailability();

    expect(isKycFlowEnabled()).toBe(false);
    expect(isKycFlowEnabled('FRA')).toBe(false);
  });

  it('keeps the previous values when a flag read throws', async () => {
    const error = jest.spyOn(console, 'error').mockImplementation(() => {});
    mockGetFeatureFlag.mockRejectedValue(new Error('storage'));

    await syncKycAvailability();

    expect(useKycAvailabilityStore.getState().hydrated).toBe(false);
    expect(isKycFlowEnabled('IND')).toBe(true);
    error.mockRestore();
  });

  it('re-renders the reactive hook when the flags change', async () => {
    const { result } = renderHook(() => useKycFlowEnabled('IND'));
    expect(result.current).toBe(true);

    setFlags(true, 'IND');
    await act(async () => {
      await syncKycAvailability();
    });

    expect(result.current).toBe(false);
  });

  it('runs the sync when remote config notifies', async () => {
    const listener = mockSubscribe.mock.calls[0][0];
    setFlags(false, '');

    listener();

    await waitFor(() => expect(isKycFlowEnabled()).toBe(false));
  });
});
