// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import React from 'react';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import type { RouteProp } from '@react-navigation/native';
import { useRoute } from '@react-navigation/native';

import { YStack } from '@selfxyz/mobile-sdk-alpha/components';
import { slate100 } from '@selfxyz/mobile-sdk-alpha/constants/colors';
import IDSelection from '@selfxyz/mobile-sdk-alpha/onboarding/id-selection-screen';

import { DocumentFlowNavBar } from '@/components/navbar/DocumentFlowNavBar';
import { useKycFlowEnabled } from '@/integrations/kyc';
import type { RootStackParamList } from '@/navigation';
import { extraYPadding } from '@/utils/styleUtils';

type IDPickerScreenRouteProp = RouteProp<RootStackParamList, 'IDPicker'>;

const IDPickerScreen: React.FC = () => {
  const route = useRoute<IDPickerScreenRouteProp>();
  const { countryCode = '', documentTypes = [] } = route.params || {};
  const bottom = useSafeAreaInsets().bottom;
  const showKycOption = useKycFlowEnabled(countryCode);

  return (
    <YStack
      flex={1}
      backgroundColor={slate100}
      paddingBottom={bottom + extraYPadding + 24}
    >
      <DocumentFlowNavBar title="GETTING STARTED" />
      <IDSelection
        countryCode={countryCode}
        documentTypes={documentTypes}
        showKycOption={showKycOption}
      />
    </YStack>
  );
};

export default IDPickerScreen;
