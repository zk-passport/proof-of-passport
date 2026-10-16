// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { act, renderHook, waitFor } from '@testing-library/react-native';

import {
  trackBranchEvent,
  trackOnboardingStep,
  useSelfClient,
} from '@selfxyz/mobile-sdk-alpha';
import {
  KycEvents,
  OnboardingEvents,
} from '@selfxyz/mobile-sdk-alpha/constants/analytics';

import type { AlertModalParams } from '@/components/AlertModal';
import { useKycLauncher } from '@/hooks/useKycLauncher';
import {
  createKycSession,
  isKycFlowEnabled,
  launchKycVerification as startKycVerification,
} from '@/integrations/kyc';
import { KYC_FAUCET_NOTICE_COPY } from '@/integrations/kyc/faucetNotice';
import { useFeedback } from '@/providers/feedbackProvider';
import { getKycDocumentCount } from '@/providers/passportDataProvider';

const mockNavigate = jest.fn();

jest.mock('@react-navigation/native', () => ({
  useNavigation: () => ({ navigate: mockNavigate }),
}));

jest.mock('@selfxyz/mobile-sdk-alpha', () => ({
  __esModule: true,
  sanitizeErrorMessage: (msg: unknown) => String(msg),
  trackBranchEvent: jest.fn(),
  trackOnboardingStep: jest.fn(),
  useSelfClient: jest.fn(),
}));

jest.mock('@selfxyz/mobile-sdk-alpha/constants/analytics', () => ({
  OnboardingEvents: { SCAN_STARTED: 'Onboarding: Document Scan Started' },
  KycEvents: {
    FAUCET_NOTICE_CONTINUED: 'KYC: Faucet Notice Continued',
    FAUCET_NOTICE_DECLINED: 'KYC: Faucet Notice Declined',
    FAUCET_NOTICE_SHOWN: 'KYC: Faucet Notice Shown',
    SESSION_REQUESTED: 'KYC: Session Requested',
    SESSION_CREATED: 'KYC: Session Created',
    PROVIDER_OPENED: 'KYC: Provider Opened',
    PROVIDER_CLOSED: 'KYC: Provider Closed',
    RETRY_TRIGGERED: 'KYC: Retry Triggered',
  },
}));

jest.mock('@/integrations/kyc', () => {
  const isKycFlowEnabledMock = jest.fn(() => true);
  return {
    createKycSession: jest.fn(),
    isKycFlowEnabled: isKycFlowEnabledMock,
    launchKycVerification: jest.fn(),
    useKycFlowEnabled: (countryCode?: string) =>
      isKycFlowEnabledMock(countryCode),
  };
});

jest.mock('@/providers/feedbackProvider', () => ({
  useFeedback: jest.fn(),
}));

jest.mock('@/providers/passportDataProvider', () => ({
  getKycDocumentCount: jest.fn(),
}));

const mockGetState = jest.fn();
jest.mock('@/stores/pendingKycStore', () => ({
  usePendingKycStore: {
    getState: () => mockGetState(),
  },
}));

const mockCreateKycSession = createKycSession as jest.MockedFunction<
  typeof createKycSession
>;
const mockIsKycFlowEnabled = isKycFlowEnabled as jest.MockedFunction<
  typeof isKycFlowEnabled
>;
const mockStartKycVerification = startKycVerification as jest.MockedFunction<
  typeof startKycVerification
>;
const mockTrackOnboardingStep = trackOnboardingStep as jest.MockedFunction<
  typeof trackOnboardingStep
>;
const mockTrackBranchEvent = trackBranchEvent as jest.MockedFunction<
  typeof trackBranchEvent
>;
const mockUseSelfClient = useSelfClient as jest.MockedFunction<
  typeof useSelfClient
>;
const mockUseFeedback = useFeedback as jest.MockedFunction<typeof useFeedback>;
const mockGetKycDocumentCount = getKycDocumentCount as jest.MockedFunction<
  typeof getKycDocumentCount
>;

describe('useKycLauncher', () => {
  const selfClientStub = { trackEvent: jest.fn() };
  const mockShowModal = jest.fn<void, [AlertModalParams]>();
  const noticeModals = () =>
    mockShowModal.mock.calls
      .map(([params]) => params)
      .filter(params => params.titleText === KYC_FAUCET_NOTICE_COPY.titleText);

  beforeEach(() => {
    jest.clearAllMocks();
    mockIsKycFlowEnabled.mockReturnValue(true);
    // Default: the user accepts the faucet notice so the provider flow runs.
    mockShowModal.mockImplementation(params => {
      if (params.buttonText === KYC_FAUCET_NOTICE_COPY.continueText) {
        Promise.resolve(params.onButtonPress()).catch(() => undefined);
      }
    });
    mockUseSelfClient.mockReturnValue(
      selfClientStub as unknown as ReturnType<typeof useSelfClient>,
    );
    mockUseFeedback.mockReturnValue({
      showModal: mockShowModal,
    } as unknown as ReturnType<typeof useFeedback>);
    mockGetState.mockReturnValue({ pendingVerifications: [] });
    mockGetKycDocumentCount.mockResolvedValue(0);
    mockCreateKycSession.mockResolvedValue({
      sessionId: 'session-1',
      sessionToken: 'token-1',
    } as Awaited<ReturnType<typeof createKycSession>>);
    mockStartKycVerification.mockResolvedValue({
      type: 'cancelled',
    } as Awaited<ReturnType<typeof startKycVerification>>);
  });

  it('emits SCAN_STARTED only after createKycSession succeeds', async () => {
    const callOrder: string[] = [];
    mockTrackOnboardingStep.mockImplementation(((..._args: unknown[]) => {
      callOrder.push('trackOnboardingStep');
    }) as unknown as typeof trackOnboardingStep);
    mockCreateKycSession.mockImplementation(async () => {
      callOrder.push('createKycSession');
      return { sessionId: 'sess-1', sessionToken: 'tok-1' } as Awaited<
        ReturnType<typeof createKycSession>
      >;
    });
    mockStartKycVerification.mockImplementation(async () => {
      callOrder.push('launchKycVerification');
      return { type: 'cancelled' } as Awaited<
        ReturnType<typeof startKycVerification>
      >;
    });

    const { result } = renderHook(() =>
      useKycLauncher({ countryCode: 'US', onCancel: jest.fn() }),
    );

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(callOrder).toEqual([
      'createKycSession',
      'trackOnboardingStep',
      'launchKycVerification',
    ]);
    expect(mockTrackOnboardingStep).toHaveBeenCalledWith(
      selfClientStub,
      OnboardingEvents.SCAN_STARTED,
      { branch: 'kyc' },
    );
  });

  it('does not emit SCAN_STARTED when createKycSession fails', async () => {
    const consoleErrorSpy = jest
      .spyOn(console, 'error')
      .mockImplementation(() => {});

    mockCreateKycSession.mockRejectedValue(new Error('network down'));

    const onError = jest.fn();
    const { result } = renderHook(() =>
      useKycLauncher({ countryCode: 'US', onError }),
    );

    await act(async () => {
      await result.current.launchKycVerification();
    });

    await waitFor(() => expect(onError).toHaveBeenCalled());

    expect(mockTrackOnboardingStep).not.toHaveBeenCalled();
    expect(mockStartKycVerification).not.toHaveBeenCalled();
    expect(mockTrackBranchEvent).not.toHaveBeenCalledWith(
      selfClientStub,
      expect.stringMatching(/^KYC: Session Created$/),
      expect.anything(),
    );

    consoleErrorSpy.mockRestore();
  });

  it('calls createKycSession when no pending verification and 0 KYC IDs', async () => {
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockCreateKycSession).toHaveBeenCalledTimes(1);
  });

  it('blocks launch when pending verification exists', async () => {
    mockGetState.mockReturnValue({
      pendingVerifications: [
        {
          sessionId: '1',
          status: 'pending',
          timeoutAt: Date.now() + 60_000,
        },
      ],
    });
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Verification in progress',
        bodyText:
          "You already have a KYC verification being processed. We'll notify you when it's ready.",
      }),
    );
  });

  it('blocks launch when processing verification exists', async () => {
    mockGetState.mockReturnValue({
      pendingVerifications: [
        {
          sessionId: '1',
          status: 'processing',
          timeoutAt: Date.now() + 60_000,
        },
      ],
    });
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Verification in progress',
        bodyText:
          "You already have a KYC verification being processed. We'll notify you when it's ready.",
      }),
    );
  });

  it('blocks launch when an expired pending verification still exists in the store', async () => {
    mockGetState.mockReturnValue({
      pendingVerifications: [
        {
          sessionId: '1',
          status: 'pending',
          timeoutAt: Date.now() - 1_000,
        },
      ],
    });
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockTrackOnboardingStep).not.toHaveBeenCalled();
    expect(mockTrackBranchEvent).not.toHaveBeenCalled();
    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockStartKycVerification).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Verification in progress',
      }),
    );
  });

  it('blocks launch when an expired processing verification still exists in the store', async () => {
    mockGetState.mockReturnValue({
      pendingVerifications: [
        {
          sessionId: '1',
          status: 'processing',
          timeoutAt: Date.now() - 1_000,
        },
      ],
    });
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockTrackOnboardingStep).not.toHaveBeenCalled();
    expect(mockTrackBranchEvent).not.toHaveBeenCalled();
    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockStartKycVerification).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Verification in progress',
      }),
    );
  });

  it('blocks launch when 3 KYC IDs exist', async () => {
    mockGetKycDocumentCount.mockResolvedValue(3);
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Maximum verifications reached',
        bodyText:
          'You can have up to 3 verified IDs. Remove one before starting a new verification.',
      }),
    );
  });

  it('blocks launch when more than 3 KYC IDs exist', async () => {
    mockGetKycDocumentCount.mockResolvedValue(4);
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockTrackOnboardingStep).not.toHaveBeenCalled();
    expect(mockTrackBranchEvent).not.toHaveBeenCalled();
    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockStartKycVerification).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Maximum verifications reached',
      }),
    );
  });

  it('calls createKycSession when 2 KYC IDs exist and no pending', async () => {
    mockGetKycDocumentCount.mockResolvedValue(2);
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockCreateKycSession).toHaveBeenCalledTimes(1);
  });

  it('shows pending modal first when pending and max IDs both exist', async () => {
    mockGetState.mockReturnValue({
      pendingVerifications: [
        {
          sessionId: '1',
          status: 'pending',
          timeoutAt: Date.now() + 60_000,
        },
      ],
    });
    mockGetKycDocumentCount.mockResolvedValue(3);
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledTimes(1);
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Verification in progress',
      }),
    );
    expect(mockShowModal).not.toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Maximum verifications reached',
      }),
    );
    expect(mockGetKycDocumentCount).not.toHaveBeenCalled();
  });

  it('shows a dedicated modal when the KYC document count cannot be verified', async () => {
    mockGetKycDocumentCount.mockRejectedValue(
      new Error('keychain read failed'),
    );
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockTrackOnboardingStep).not.toHaveBeenCalled();
    expect(mockTrackBranchEvent).not.toHaveBeenCalled();
    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockStartKycVerification).not.toHaveBeenCalled();
    expect(mockShowModal).toHaveBeenCalledWith(
      expect.objectContaining({
        titleText: 'Unable to verify verification limit',
        bodyText:
          "We couldn't confirm how many verified IDs are stored. Please try again.",
      }),
    );
  });

  it('shows the faucet notice after the pre-checks and before creating a session', async () => {
    const callOrder: string[] = [];
    mockShowModal.mockImplementation(params => {
      if (params.buttonText === KYC_FAUCET_NOTICE_COPY.continueText) {
        callOrder.push('notice');
        Promise.resolve(params.onButtonPress()).catch(() => undefined);
      }
    });
    mockCreateKycSession.mockImplementation(async () => {
      callOrder.push('createKycSession');
      return { sessionId: 'sess-1', sessionToken: 'tok-1' } as Awaited<
        ReturnType<typeof createKycSession>
      >;
    });

    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));
    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(callOrder).toEqual(['notice', 'createKycSession']);
    expect(noticeModals()[0]).toMatchObject({
      bodyText: expect.stringContaining('Google USAT mainnet faucet'),
      secondaryButtonText: KYC_FAUCET_NOTICE_COPY.goBackText,
    });
    expect(selfClientStub.trackEvent).toHaveBeenCalledWith(
      KycEvents.FAUCET_NOTICE_SHOWN,
    );
    expect(selfClientStub.trackEvent).toHaveBeenCalledWith(
      KycEvents.FAUCET_NOTICE_CONTINUED,
    );
  });

  it('does not create a session when the user backs out of the faucet notice', async () => {
    mockShowModal.mockImplementation(params => {
      if (params.buttonText === KYC_FAUCET_NOTICE_COPY.continueText) {
        Promise.resolve(params.onSecondaryButtonPress?.()).catch(
          () => undefined,
        );
      }
    });

    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));
    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(noticeModals()).toHaveLength(1);
    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockStartKycVerification).not.toHaveBeenCalled();
    expect(mockTrackBranchEvent).not.toHaveBeenCalled();
    expect(selfClientStub.trackEvent).toHaveBeenCalledWith(
      KycEvents.FAUCET_NOTICE_DECLINED,
    );
    expect(result.current.isLoading).toBe(false);
  });

  it('evaluates availability against the document country', () => {
    renderHook(() => useKycLauncher({ countryCode: 'IND' }));

    expect(mockIsKycFlowEnabled).toHaveBeenCalledWith('IND');
  });

  it('does not create a session for a disabled country', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    mockIsKycFlowEnabled.mockImplementation(
      (countryCode?: string) => countryCode !== 'IND',
    );
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'IND' }));

    expect(result.current.isKycAvailable).toBe(false);
    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(mockCreateKycSession).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('re-checks availability after the faucet notice before creating a session', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));
    expect(result.current.isKycAvailable).toBe(true);

    // The flag flips while the notice is on screen; the continuation must
    // observe the new value.
    mockShowModal.mockImplementation(params => {
      if (params.buttonText === KYC_FAUCET_NOTICE_COPY.continueText) {
        mockIsKycFlowEnabled.mockReturnValue(false);
        Promise.resolve(params.onButtonPress()).catch(() => undefined);
      }
    });

    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(noticeModals().length).toBeGreaterThan(0);
    expect(mockCreateKycSession).not.toHaveBeenCalled();
    expect(mockStartKycVerification).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  describe('when the KYC flow is disabled', () => {
    beforeEach(() => {
      mockIsKycFlowEnabled.mockReturnValue(false);
    });

    it('reports the flow as unavailable and ignores launch requests', async () => {
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const { result } = renderHook(() =>
        useKycLauncher({ countryCode: 'US' }),
      );

      expect(result.current.isKycAvailable).toBe(false);

      await act(async () => {
        await result.current.launchKycVerification();
      });

      expect(mockShowModal).not.toHaveBeenCalled();
      expect(mockGetKycDocumentCount).not.toHaveBeenCalled();
      expect(mockCreateKycSession).not.toHaveBeenCalled();
      expect(mockStartKycVerification).not.toHaveBeenCalled();
      expect(result.current.isLoading).toBe(false);
      warn.mockRestore();
    });

    it('runs the dismiss handler directly instead of offering the fallback modal', () => {
      const onDismiss = jest.fn();
      const { result } = renderHook(() =>
        useKycLauncher({ countryCode: 'US' }),
      );

      act(() => {
        result.current.showKycFallbackModal(onDismiss);
      });

      expect(onDismiss).toHaveBeenCalledTimes(1);
      expect(mockShowModal).not.toHaveBeenCalled();
    });
  });

  it('does not show the faucet notice when a pre-check blocks the launch', async () => {
    mockGetKycDocumentCount.mockResolvedValue(3);

    const { result } = renderHook(() => useKycLauncher({ countryCode: 'US' }));
    await act(async () => {
      await result.current.launchKycVerification();
    });

    expect(noticeModals()).toHaveLength(0);
  });
});
