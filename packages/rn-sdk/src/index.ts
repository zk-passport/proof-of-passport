// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

export {
  SelfVerification,
  type SelfVerificationProps,
  type VerificationRequest,
  type VerificationResult,
  type SelfSdkError,
  type LoadDiagnosticEvent,
  type LoadDiagnosticKind,
  type LoadErrorInfo,
} from './SelfVerification';

export { WebViewLoadEvents } from './analytics-events';

export { MessageRouter } from './bridge/MessageRouter';
export {
  KmpBridgeTransport,
  type KmpBridgeTransportConfig,
} from './bridge/KmpBridgeTransport';

export { type BridgeHandler, BridgeHandlerError } from './bridge/types';

export {
  AnalyticsHandler,
  type AnalyticsSink,
  HapticHandler,
  NavigationHandler,
  type NavigationCallbacks,
  DocumentsHandler,
  type DocumentsStore,
  KeychainHandler,
  type SecureStorageStore,
  CryptoHandler,
  type SelfCryptoModule,
  LifecycleHandler,
  type OperatingMode,
  createHandlers,
  type HandlersConfig,
} from './handlers';
