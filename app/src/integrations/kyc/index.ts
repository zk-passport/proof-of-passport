// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

export type {
  ApplicantInfoSerialized,
  KycVerificationResult,
  SessionResponse,
} from '@/integrations/kyc/types';
export { KYC_PROVIDER } from '@/integrations/kyc/constants';
export {
  type KycLaunchConfig,
  createKycSession,
  launchKycVerification,
} from '@/integrations/kyc/kycService';
export {
  isKycFlowEnabled,
  useKycFlowEnabled,
} from '@/stores/kycAvailabilityStore';
