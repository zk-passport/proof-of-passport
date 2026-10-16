// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import React, { useCallback } from 'react';
import { YStack } from 'tamagui';
import type { RouteProp } from '@react-navigation/native';
import { useNavigation, useRoute } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';

import {
  failOnboardingAttempt,
  setOnboardingBranch,
  trackBranchEvent,
  trackOnboardingStep,
  useSelfClient,
} from '@selfxyz/mobile-sdk-alpha';
import {
  BodyText,
  ButtonsContainer,
  PrimaryButton,
  SecondaryButton,
} from '@selfxyz/mobile-sdk-alpha/components';
import {
  KycEvents,
  OnboardingEvents,
} from '@selfxyz/mobile-sdk-alpha/constants/analytics';
import {
  black,
  slate100,
  slate400,
  white,
} from '@selfxyz/mobile-sdk-alpha/constants/colors';
import { advercase, dinot } from '@selfxyz/mobile-sdk-alpha/constants/fonts';

import EPassportLogo from '@/assets/icons/epassport_logo.svg';
import { DocumentFlowNavBar } from '@/components/navbar/DocumentFlowNavBar';
import useHapticNavigation from '@/hooks/useHapticNavigation';
import { buttonTap } from '@/integrations/haptics';
import {
  createKycSession,
  isKycFlowEnabled,
  KYC_PROVIDER,
  launchKycVerification,
} from '@/integrations/kyc';
import { confirmKycFaucetNotice } from '@/integrations/kyc/faucetNotice';
import { ExpandableBottomLayout } from '@/layouts/ExpandableBottomLayout';
import type { RootStackParamList } from '@/navigation';
import { useFeedback } from '@/providers/feedbackProvider';

type LogoConfirmationScreenRouteProp = RouteProp<
  RootStackParamList,
  'LogoConfirmation'
>;

const LogoConfirmationScreen: React.FC = () => {
  const route = useRoute<LogoConfirmationScreenRouteProp>();
  const { countryCode } = route.params;
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { showModal } = useFeedback();
  const navigateToOnboarding = useHapticNavigation('DocumentOnboarding');
  const selfClient = useSelfClient();

  const handleConfirm = useCallback(() => {
    buttonTap();
    navigateToOnboarding();
  }, [navigateToOnboarding]);

  const showKycUnavailableNotice = useCallback(() => {
    showModal({
      titleText: 'Document Not Supported',
      bodyText:
        'Registration currently requires a document with a biometric chip. Please use a passport or an ID card that carries this symbol.',
      buttonText: 'OK',
      onButtonPress: () => {},
    });
  }, [showModal]);

  const runKycFlow = useCallback(async () => {
    if (!isKycFlowEnabled(countryCode)) {
      showKycUnavailableNotice();
      return;
    }
    let scanStarted = false;
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
      trackBranchEvent(selfClient, KycEvents.SESSION_CREATED, {
        provider: KYC_PROVIDER,
        duration_seconds: parseFloat(
          ((Date.now() - sessionRequestedAt) / 1000).toFixed(2),
        ),
      });
      trackOnboardingStep(selfClient, OnboardingEvents.SCAN_STARTED, {
        branch: 'kyc',
      });
      scanStarted = true;
      providerOpenedAt = Date.now();
      trackBranchEvent(selfClient, KycEvents.PROVIDER_OPENED, {
        provider: KYC_PROVIDER,
      });
      const result = await launchKycVerification(session.sessionToken);
      const providerDurationSeconds = parseFloat(
        ((Date.now() - providerOpenedAt) / 1000).toFixed(2),
      );

      // User cancelled/dismissed without completing verification
      if (result.type === 'cancelled') {
        trackBranchEvent(selfClient, KycEvents.PROVIDER_CLOSED, {
          provider: KYC_PROVIDER,
          outcome: 'cancelled',
          duration_seconds: providerDurationSeconds,
        });
        failOnboardingAttempt(selfClient, 'scan_started', 'kyc_cancelled');
        return;
      }

      // Verification failed (provider error/rejection)
      if (result.type === 'failed') {
        console.error(
          'KYC verification failed:',
          result.error?.type ?? 'unknown',
        );
        trackBranchEvent(selfClient, KycEvents.PROVIDER_CLOSED, {
          provider: KYC_PROVIDER,
          outcome: 'failed',
          error_code: result.error?.type,
          duration_seconds: providerDurationSeconds,
        });
        failOnboardingAttempt(
          selfClient,
          'scan_started',
          `kyc_failed:${result.error?.type ?? 'unknown'}`,
        );
        navigation.navigate('KycFailure', {
          countryCode,
          canRetry: true,
        });
        return;
      }

      // Verification succeeded - navigate to KycSuccessScreen
      trackBranchEvent(selfClient, KycEvents.PROVIDER_CLOSED, {
        provider: KYC_PROVIDER,
        outcome: 'completed',
        duration_seconds: providerDurationSeconds,
      });
      trackOnboardingStep(selfClient, OnboardingEvents.SCAN_SUCCEEDED, {
        branch: 'kyc',
      });
      navigation.navigate('KycSuccess', { sessionId: session.sessionId });
    } catch {
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
      console.error('Error launching KYC verification');
      failOnboardingAttempt(
        selfClient,
        scanStarted ? 'scan_started' : 'pre_start',
        scanStarted ? 'kyc_launch_error' : 'kyc_session_error',
      );
      showModal({
        titleText: 'Error',
        bodyText: 'Unable to start verification. Please try again.',
        buttonText: 'OK',
        onButtonPress: () => {},
      });
    }
  }, [
    countryCode,
    navigation,
    selfClient,
    showKycUnavailableNotice,
    showModal,
  ]);

  const handleNotFound = useCallback(() => {
    buttonTap();
    if (!isKycFlowEnabled(countryCode)) {
      showKycUnavailableNotice();
      return;
    }
    // "No" on the chip-symbol check routes through the KYC provider —
    // update the canonical funnel branch accordingly.
    setOnboardingBranch('kyc');
    showModal({
      titleText: 'Document Not Supported',
      bodyText:
        "To complete registration of a document without a biometric chip, you'll be redirected to our third party verification partner.",
      buttonText: 'Proceed with an external verifier',
      onButtonPress: () =>
        confirmKycFaucetNotice(
          showModal,
          { onContinue: runKycFlow },
          selfClient,
        ),
    });
  }, [
    countryCode,
    runKycFlow,
    selfClient,
    showKycUnavailableNotice,
    showModal,
  ]);

  return (
    <ExpandableBottomLayout.Layout backgroundColor={slate100}>
      <DocumentFlowNavBar title="GETTING STARTED" />
      <ExpandableBottomLayout.TopSection backgroundColor={slate100}>
        <YStack alignItems="center" gap={24} maxWidth={340}>
          <BodyText
            style={{
              fontSize: 20,
              fontFamily: advercase,
              textAlign: 'center',
              color: black,
            }}
          >
            Does your document have this symbol?
          </BodyText>

          <YStack
            backgroundColor={white}
            borderRadius={16}
            padding={24}
            shadowColor={black}
            shadowOffset={{ width: 0, height: 2 }}
            shadowOpacity={0.1}
            shadowRadius={8}
            elevation={4}
          >
            <EPassportLogo width={160} height={98} />
          </YStack>

          <BodyText
            style={{
              fontSize: 16,
              fontFamily: dinot,
              textAlign: 'center',
              color: slate400,
            }}
          >
            This symbol indicates your document has a biometric chip, which is
            required for registration.
          </BodyText>
        </YStack>
      </ExpandableBottomLayout.TopSection>

      <ExpandableBottomLayout.BottomSection backgroundColor={slate100}>
        <ButtonsContainer>
          <PrimaryButton onPress={handleConfirm}>Yes</PrimaryButton>
          <SecondaryButton onPress={handleNotFound}>No</SecondaryButton>
        </ButtonsContainer>
      </ExpandableBottomLayout.BottomSection>
    </ExpandableBottomLayout.Layout>
  );
};

export default LogoConfirmationScreen;
