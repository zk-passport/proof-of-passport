// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// Mock ConfirmIdentificationScreen to avoid PixelRatio issues
import type { ReactNode } from 'react';
import { act, renderHook } from '@testing-library/react-native';

import { useKycFaucetNoticeStore } from '@/stores/kycFaucetNoticeStore';
import { useSettingStore } from '@/stores/settingStore';

let mockSdkProviderProps: Record<string, unknown> | undefined;

jest.mock('@/assets/images/512w.png', () => 'mock-512w-image');
jest.mock('@/assets/images/nfc.png', () => 'mock-nfc-image');
jest.mock('react-native-localize', () => {
  const getLocales = jest.fn(() => [
    {
      countryCode: 'US',
      languageTag: 'en-US',
      languageCode: 'en',
      isRTL: false,
    },
  ]);
  const getCountry = jest.fn(() => 'US');

  return {
    __esModule: true,
    default: {
      getLocales,
      getCountry,
    },
    getLocales,
    getCountry,
  };
});

jest.mock('@/navigation', () => {
  const navigationRef = {
    isReady: jest.fn(() => false),
    navigate: jest.fn(),
  };
  return {
    __esModule: true,
    navigationRef,
    default: navigationRef,
  };
});

jest.mock(
  '@selfxyz/mobile-sdk-alpha/onboarding/confirm-identification',
  () => ({
    ConfirmIdentificationScreen: ({ children }: any) => children,
  }),
);

jest.mock('@selfxyz/mobile-sdk-alpha', () => {
  const mockClient = {
    getSelfAppState: jest.fn(() => ({})),
    getProtocolState: jest.fn(() => ({})),
    getDeepLinksState: jest.fn(() => ({})),
  };
  const mockSdkProvider = ({ children, ...props }: any) => {
    mockSdkProviderProps = props;
    return <mock-sdk-provider>{children}</mock-sdk-provider>;
  };

  const createListenersMap = () => {
    const map = new Map();
    return {
      map,
      addListener: (event: string, callback: (...args: unknown[]) => void) => {
        map.set(event, callback);
      },
    };
  };

  const SdkEvents = {
    PROVING_PASSPORT_DATA_NOT_FOUND: 'PROVING_PASSPORT_DATA_NOT_FOUND',
    PROVING_ACCOUNT_VERIFIED_SUCCESS: 'PROVING_ACCOUNT_VERIFIED_SUCCESS',
    PROVING_REGISTER_ERROR_OR_FAILURE: 'PROVING_REGISTER_ERROR_OR_FAILURE',
    PROVING_ACCOUNT_VERIFIED_PENDING: 'PROVING_ACCOUNT_VERIFIED_PENDING',
    PROVING_ACCOUNT_VERIFIED_FAILURE: 'PROVING_ACCOUNT_VERIFIED_FAILURE',
    DOCUMENT_TYPE_SELECTED: 'DOCUMENT_TYPE_SELECTED',
    DOCUMENT_COUNTRY_SELECTED: 'DOCUMENT_COUNTRY_SELECTED',
  };

  return {
    __esModule: true,
    sanitizeErrorMessage: (msg: unknown) => String(msg),
    trackBranchEvent: jest.fn(),
    trackOnboardingStep: jest.fn(),
    useSelfClient: jest.fn(() => mockClient),
    SelfClientProvider: mockSdkProvider,
    createListenersMap,
    impactLight: jest.fn(),
    reactNativeScannerAdapter: {},
    SdkEvents,
    useMRZStore: { getState: () => ({ update: jest.fn() }) },
    webNFCScannerShim: {},
  };
});

jest.mock('@/integrations/kyc', () => ({
  createKycSession: jest.fn(),
  isKycFlowEnabled: jest.fn(() => true),
  launchKycVerification: jest.fn(),
  KYC_PROVIDER: 'didit',
}));

let useSelfClient: () => unknown;
let SelfClientProvider: ({ children }: { children: ReactNode }) => JSX.Element;
let SdkEvents: Record<string, string>;
let trackBranchEvent: jest.Mock;
let trackOnboardingStep: jest.Mock;
let createKycSession: jest.Mock;
let isKycFlowEnabled: jest.Mock;
let launchKycVerification: jest.Mock;
let navigationRef: { isReady: jest.Mock; navigate: jest.Mock };

beforeAll(() => {
  ({
    useSelfClient,
    SdkEvents,
    trackBranchEvent,
    trackOnboardingStep,
  } = require('@selfxyz/mobile-sdk-alpha'));
  ({ SelfClientProvider } = require('@/providers/selfClientProvider'));
  ({
    createKycSession,
    isKycFlowEnabled,
    launchKycVerification,
  } = require('@/integrations/kyc'));
  ({ navigationRef } = require('@/navigation'));
});

describe('SelfClientProvider', () => {
  beforeEach(() => {
    mockSdkProviderProps = undefined;
    useSettingStore.setState(useSettingStore.getInitialState(), true);
    navigationRef.isReady.mockReturnValue(false);
    isKycFlowEnabled.mockReturnValue(true);
    useKycFaucetNoticeStore.getState().close();
  });

  it('memoises the client instance', () => {
    const wrapper = ({ children }: { children: ReactNode }) => (
      <SelfClientProvider>{children}</SelfClientProvider>
    );
    const { result, rerender } = renderHook(() => useSelfClient(), { wrapper });
    const first = result.current;
    rerender();
    expect(result.current).toBe(first);
  });

  it('wires Web Crypto hashing and network adapters', async () => {
    const originalFetch = (global as any).fetch;
    const originalWebSocket = (global as any).WebSocket;

    try {
      const fetchSpy = jest.fn(async () => new Response(null));
      (global as any).fetch = fetchSpy;
      class MockSocket {
        url: string;
        constructor(url: string) {
          this.url = url;
        }
        addEventListener() {}
        send() {}
        close() {}
      }
      (global as any).WebSocket = MockSocket;

      const wrapper = ({ children }: { children: ReactNode }) => (
        <SelfClientProvider>{children}</SelfClientProvider>
      );
      renderHook(() => useSelfClient(), { wrapper });

      const data = new TextEncoder().encode('hello');
      const digest = await crypto.subtle.digest('SHA-256', data);
      expect(digest.byteLength).toBeGreaterThan(0);

      await expect(fetch('https://example.com')).resolves.toBeDefined();
      const socket = new WebSocket('ws://example.com');
      expect(typeof (socket as any).send).toBe('function');
    } finally {
      // Cleanup - restore original globals
      (global as any).fetch = originalFetch;
      (global as any).WebSocket = originalWebSocket;
    }
  });

  it('consumes shouldBypassDocumentRegistrationCheck as a one-shot flag', () => {
    act(() => {
      useSettingStore.getState().armTestRegistrationCircuit();
    });

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SelfClientProvider>{children}</SelfClientProvider>
    );
    renderHook(() => useSelfClient(), { wrapper });

    const config = mockSdkProviderProps?.config as
      | {
          devConfig?: {
            shouldBypassDocumentRegistrationCheck?: () => boolean;
            shouldBypassDscRegistrationCheck?: () => boolean;
          };
        }
      | undefined;

    expect(config?.devConfig?.shouldBypassDocumentRegistrationCheck?.()).toBe(
      true,
    );
    expect(config?.devConfig?.shouldBypassDocumentRegistrationCheck?.()).toBe(
      false,
    );
    expect(useSettingStore.getState().testRegistrationCircuitArmed).toBe(false);
  });

  it('consumes shouldBypassDscRegistrationCheck as a one-shot flag', () => {
    act(() => {
      useSettingStore.getState().armTestDscCircuit();
    });

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SelfClientProvider>{children}</SelfClientProvider>
    );
    renderHook(() => useSelfClient(), { wrapper });

    const config = mockSdkProviderProps?.config as
      | {
          devConfig?: {
            shouldBypassDocumentRegistrationCheck?: () => boolean;
            shouldBypassDscRegistrationCheck?: () => boolean;
          };
        }
      | undefined;

    expect(config?.devConfig?.shouldBypassDscRegistrationCheck?.()).toBe(true);
    expect(config?.devConfig?.shouldBypassDscRegistrationCheck?.()).toBe(false);
    expect(useSettingStore.getState().testDscCircuitArmed).toBe(false);
  });

  it('keeps document and DSC bypasses independent', () => {
    act(() => {
      useSettingStore.getState().armTestRegistrationCircuit();
    });

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SelfClientProvider>{children}</SelfClientProvider>
    );
    renderHook(() => useSelfClient(), { wrapper });

    const config = mockSdkProviderProps?.config as
      | {
          devConfig?: {
            shouldBypassDocumentRegistrationCheck?: () => boolean;
            shouldBypassDscRegistrationCheck?: () => boolean;
          };
        }
      | undefined;

    // DSC bypass is not armed even though the document bypass is.
    expect(config?.devConfig?.shouldBypassDscRegistrationCheck?.()).toBe(false);
    expect(config?.devConfig?.shouldBypassDocumentRegistrationCheck?.()).toBe(
      true,
    );
  });

  // Path C invariant (ANA-12): SCAN_STARTED MUST fire before any KYC branch
  // event, otherwise trackBranchEvent no-ops because currentAttempt is null
  // and SESSION_REQUESTED is silently dropped from the funnel.
  it('emits SCAN_STARTED before the first KYC branch event on the direct KYC path', async () => {
    const callOrder: string[] = [];
    navigationRef.isReady.mockReturnValue(true);

    (trackBranchEvent as jest.Mock).mockImplementation((...args: unknown[]) => {
      callOrder.push(`branch:${String(args[1])}`);
    });
    (trackOnboardingStep as jest.Mock).mockImplementation(
      (...args: unknown[]) => {
        callOrder.push(`onboarding:${String(args[1])}`);
      },
    );
    (createKycSession as jest.Mock).mockImplementation(async () => {
      callOrder.push('createKycSession');
      return { sessionId: 'session-1', sessionToken: 'token-1' };
    });
    (launchKycVerification as jest.Mock).mockImplementation(async () => {
      callOrder.push('launchKycVerification');
      return { type: 'cancelled' };
    });

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SelfClientProvider>{children}</SelfClientProvider>
    );
    renderHook(() => useSelfClient(), { wrapper });

    const providerListeners = mockSdkProviderProps?.listeners as Map<
      string,
      (payload: { documentType: string; countryCode?: string }) => void
    >;
    const onDocumentTypeSelected = providerListeners.get(
      SdkEvents.DOCUMENT_TYPE_SELECTED,
    );

    expect(onDocumentTypeSelected).toBeDefined();

    await act(async () => {
      await onDocumentTypeSelected?.({
        documentType: 'kyc',
        countryCode: 'US',
      });
    });

    // The faucet-incompatibility notice gates the provider launch; nothing
    // runs until the user continues.
    expect(useKycFaucetNoticeStore.getState().isOpen).toBe(true);
    expect(callOrder).toEqual([]);

    await act(async () => {
      await useKycFaucetNoticeStore.getState().onContinue?.();
    });

    expect(callOrder).toEqual([
      'onboarding:Onboarding: Document Scan Started',
      `branch:KYC: Session Requested`,
      'createKycSession',
      `branch:KYC: Session Created`,
      `branch:KYC: Provider Opened`,
      'launchKycVerification',
      `branch:KYC: Provider Closed`,
    ]);

    const scanStartedIdx = callOrder.indexOf(
      'onboarding:Onboarding: Document Scan Started',
    );
    const firstBranchIdx = callOrder.findIndex(entry =>
      entry.startsWith('branch:'),
    );
    expect(scanStartedIdx).toBeLessThan(firstBranchIdx);

    navigationRef.isReady.mockReturnValue(false);
  });
  describe('when the KYC flow is disabled', () => {
    const renderProvider = () => {
      const wrapper = ({ children }: { children: ReactNode }) => (
        <SelfClientProvider>{children}</SelfClientProvider>
      );
      renderHook(() => useSelfClient(), { wrapper });
      return mockSdkProviderProps?.listeners as Map<
        string,
        (payload: Record<string, unknown>) => void | Promise<void>
      >;
    };

    beforeEach(() => {
      isKycFlowEnabled.mockReturnValue(false);
      navigationRef.isReady.mockReturnValue(true);
      navigationRef.navigate.mockClear();
      createKycSession.mockClear();
    });

    afterEach(() => {
      navigationRef.isReady.mockReturnValue(false);
    });

    it('drops kyc from the ID picker document types', () => {
      const listeners = renderProvider();
      listeners.get(SdkEvents.DOCUMENT_COUNTRY_SELECTED)?.({
        countryCode: 'US',
        documentTypes: ['p', 'kyc'],
      });

      expect(isKycFlowEnabled).toHaveBeenCalledWith('US');
      expect(navigationRef.navigate).toHaveBeenCalledWith('IDPicker', {
        countryCode: 'US',
        documentTypes: ['p'],
      });
    });

    it('sends the user to ComingSoon when kyc was the only option', () => {
      const listeners = renderProvider();
      listeners.get(SdkEvents.DOCUMENT_COUNTRY_SELECTED)?.({
        countryCode: 'XX',
        documentTypes: ['kyc'],
      });

      expect(navigationRef.navigate).toHaveBeenCalledWith('ComingSoon', {
        countryCode: 'XX',
      });
      expect(navigationRef.navigate).not.toHaveBeenCalledWith(
        'IDPicker',
        expect.anything(),
      );
    });

    it('routes to ComingSoon when the flag turns off while the notice is open', async () => {
      isKycFlowEnabled.mockReturnValue(true);
      const listeners = renderProvider();
      await act(async () => {
        await listeners.get(SdkEvents.DOCUMENT_TYPE_SELECTED)?.({
          documentType: 'kyc',
          countryCode: 'US',
        });
      });
      expect(useKycFaucetNoticeStore.getState().isOpen).toBe(true);

      isKycFlowEnabled.mockReturnValue(false);
      await act(async () => {
        await useKycFaucetNoticeStore.getState().onContinue?.();
      });

      expect(navigationRef.navigate).toHaveBeenCalledWith('ComingSoon', {
        countryCode: 'US',
      });
      expect(createKycSession).not.toHaveBeenCalled();
    });

    it('routes a stray kyc selection to ComingSoon without opening the notice', async () => {
      const listeners = renderProvider();
      await act(async () => {
        await listeners.get(SdkEvents.DOCUMENT_TYPE_SELECTED)?.({
          documentType: 'kyc',
          countryCode: 'US',
        });
      });

      expect(navigationRef.navigate).toHaveBeenCalledWith('ComingSoon', {
        countryCode: 'US',
      });
      expect(useKycFaucetNoticeStore.getState().isOpen).toBe(false);
      expect(createKycSession).not.toHaveBeenCalled();
    });
  });
});
