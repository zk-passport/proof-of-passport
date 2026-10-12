// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { useCallback, useState } from 'react';
import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';

import {
  sanitizeErrorMessage,
  trackBranchEvent,
  trackOnboardingStep,
  useSelfClient,
} from '@selfxyz/mobile-sdk-alpha';
import {
  KycEvents,
  OnboardingEvents,
} from '@selfxyz/mobile-sdk-alpha/constants/analytics';

import {
  createKycSession,
  KYC_PROVIDER,
  launchKycVerification as startKycVerification,
  useKycFlowEnabled,
} from '@/integrations/kyc';
import { confirmKycFaucetNotice } from '@/integrations/kyc/faucetNotice';
import type { KycVerificationResult } from '@/integrations/kyc/types';
import type { RootStackParamList } from '@/navigation';
import { useFeedback } from '@/providers/feedbackProvider';
import { getKycDocumentCount } from '@/providers/passportDataProvider';
import { usePendingKycStore } from '@/stores/pendingKycStore';

export interface UseKycLauncherOptions {
  /**
   * Country code for the user's document
   */
  countryCode: string;
  /**
   * Optional callback to handle successful verification.
   * Receives the KYC result and the sessionId from the session.
   * If not provided, defaults to navigating to KycSuccess with the sessionId.
   */
  onSuccess?: (
    result: KycVerificationResult,
    sessionId: string,
  ) => void | Promise<void>;
  /**
   * Optional callback to handle user cancellation
   */
  onCancel?: () => void | Promise<void>;
  /**
   * Optional callback to handle verification failure
   */
  onError?: (
    error: unknown,
    result?: KycVerificationResult,
  ) => void | Promise<void>;
  /**
   * Optional label for the secondary button in the fallback modal.
   */
  cancelLabel?: string;
}

/**
 * Custom hook for launching KYC verification with consistent error handling.
 *
 * Abstracts the common pattern of:
 * 1. Running the pre-launch checks and the faucet-incompatibility notice
 * 2. Creating a session
 * 3. Launching the provider SDK
 * 4. Handling errors by navigating to fallback screen
 * 5. Managing loading state
 *
 * @example
 * ```tsx
 * const { launchKycVerification, isLoading } = useKycLauncher({
 *   countryCode: 'US',
 * });
 *
 * <Button onPress={launchKycVerification} disabled={isLoading}>
 *   {isLoading ? 'Loading...' : 'Try Alternative Verification'}
 * </Button>
 * ```
 */
export const useKycLauncher = (options: UseKycLauncherOptions) => {
  const {
    countryCode,
    onSuccess,
    onCancel,
    onError,
    cancelLabel = 'Cancel Registration',
  } = options;
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { showModal } = useFeedback();
  const selfClient = useSelfClient();
  const [isLoading, setIsLoading] = useState(false);

  const runKycProviderFlow = useCallback(async () => {
    const sessionRequestedAt = Date.now();
    let providerOpenedAt: number | null = null;
    try {
      trackBranchEvent(selfClient, KycEvents.SESSION_REQUESTED, {
        provider: KYC_PROVIDER,
      });
      const session = await createKycSession({
        country: countryCode,
        nationality: countryCode,
      });
      trackOnboardingStep(selfClient, OnboardingEvents.SCAN_STARTED, {
        branch: 'kyc',
      });
      trackBranchEvent(selfClient, KycEvents.SESSION_CREATED, {
        provider: KYC_PROVIDER,
        duration_seconds: parseFloat(
          ((Date.now() - sessionRequestedAt) / 1000).toFixed(2),
        ),
      });
      providerOpenedAt = Date.now();
      const openedAt = providerOpenedAt;
      trackBranchEvent(selfClient, KycEvents.PROVIDER_OPENED, {
        provider: KYC_PROVIDER,
      });
      const result = await startKycVerification(session.sessionToken);
      const providerDurationSeconds = parseFloat(
        ((Date.now() - openedAt) / 1000).toFixed(2),
      );

      // Handle user cancellation
      if (result.type === 'cancelled') {
        trackBranchEvent(selfClient, KycEvents.PROVIDER_CLOSED, {
          provider: KYC_PROVIDER,
          outcome: 'cancelled',
          duration_seconds: providerDurationSeconds,
        });
        await onCancel?.();
        return;
      }

      // Handle verification failure
      if (result.type === 'failed') {
        const error =
          result.error?.message || result.error?.type || 'Unknown error';
        const safeError = sanitizeErrorMessage(error);
        console.error('KYC verification failed:', safeError);
        trackBranchEvent(selfClient, KycEvents.PROVIDER_CLOSED, {
          provider: KYC_PROVIDER,
          outcome: 'failed',
          error_code: result.error?.type,
          duration_seconds: providerDurationSeconds,
        });

        // Call custom error handler if provided, otherwise navigate to fallback screen
        if (onError) {
          await onError(safeError, result);
        } else {
          navigation.navigate('KycFailure', {
            countryCode,
            canRetry: true,
          });
        }
        return;
      }

      // Handle success - navigate to KycSuccess by default
      trackBranchEvent(selfClient, KycEvents.PROVIDER_CLOSED, {
        provider: KYC_PROVIDER,
        outcome: 'completed',
        duration_seconds: providerDurationSeconds,
      });
      if (onSuccess) {
        await onSuccess(result, session.sessionId);
      } else {
        navigation.navigate('KycSuccess', { sessionId: session.sessionId });
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      const safeError = sanitizeErrorMessage(errorMessage);
      console.error('Error launching alternative verification:', safeError);

      if (providerOpenedAt !== null) {
        trackBranchEvent(selfClient, KycEvents.PROVIDER_CLOSED, {
          provider: KYC_PROVIDER,
          outcome: 'failed',
          error_code: 'launch_error',
          duration_seconds: parseFloat(
            ((Date.now() - providerOpenedAt) / 1000).toFixed(2),
          ),
        });
      }

      // Call custom error handler if provided, otherwise navigate to fallback screen
      if (onError) {
        await onError(safeError);
      } else {
        navigation.navigate('KycConnectionError', { countryCode });
      }
    }
  }, [navigation, selfClient, countryCode, onSuccess, onCancel, onError]);

  const isKycAvailable = useKycFlowEnabled(countryCode);

  const launchKycVerification = useCallback(async () => {
    if (!isKycAvailable) {
      console.warn('KYC flow is disabled; ignoring launch request');
      return;
    }

    const hasPendingOrProcessingKyc = () =>
      usePendingKycStore
        .getState()
        .pendingVerifications.some(
          verification =>
            verification.status === 'pending' ||
            verification.status === 'processing',
        );

    setIsLoading(true);
    try {
      if (hasPendingOrProcessingKyc()) {
        showModal({
          titleText: 'Verification in progress',
          bodyText:
            "You already have a KYC verification being processed. We'll notify you when it's ready.",
          buttonText: 'Dismiss',
          onButtonPress: () => {},
        });
        return;
      }

      let kycDocumentCount: number;
      try {
        kycDocumentCount = await getKycDocumentCount();
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        const safeError = sanitizeErrorMessage(errorMessage);
        console.error('Unable to verify KYC document count:', safeError);
        showModal({
          titleText: 'Unable to verify verification limit',
          bodyText:
            "We couldn't confirm how many verified IDs are stored. Please try again.",
          buttonText: 'Dismiss',
          onButtonPress: () => {},
        });
        return;
      }

      if (kycDocumentCount >= 3) {
        showModal({
          titleText: 'Maximum verifications reached',
          bodyText:
            'You can have up to 3 verified IDs. Remove one before starting a new verification.',
          buttonText: 'Dismiss',
          onButtonPress: () => {},
        });
        return;
      }

      await confirmKycFaucetNotice(
        showModal,
        { onContinue: runKycProviderFlow },
        selfClient,
      );
    } finally {
      setIsLoading(false);
    }
  }, [isKycAvailable, runKycProviderFlow, selfClient, showModal]);

  const showKycFallbackModal = useCallback(
    (onDismiss: () => void) => {
      if (!isKycAvailable) {
        onDismiss();
        return;
      }
      const titleText = 'Having trouble scanning your document?';
      const bodyText =
        "You'll be redirected to our third party verification partner.";
      showModal({
        titleText,
        bodyText,
        buttonText: 'Try Alternative Verification',
        secondaryButtonText: cancelLabel,
        onButtonPress: () => {
          showModal({
            titleText,
            bodyText,
            buttonText: 'Loading...',
            disablePrimaryButton: true,
            preventDismiss: true,
            onButtonPress: () => {},
          });
          return launchKycVerification();
        },
        onSecondaryButtonPress: onDismiss,
      });
    },
    [cancelLabel, isKycAvailable, showModal, launchKycVerification],
  );

  return {
    launchKycVerification,
    showKycFallbackModal,
    isKycAvailable,
    isLoading,
  };
};
