// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { Paths } from 'expo-file-system';
import React, { useCallback, useEffect, useMemo, useRef } from 'react';
import { Platform, View } from 'react-native';
import type { RouteProp } from '@react-navigation/native';
import { useNavigation, useRoute } from '@react-navigation/native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';

import { useSelfClient } from '@selfxyz/mobile-sdk-alpha';
import {
  type AnalyticsSink,
  type DocumentsStore,
  type LoadDiagnosticEvent,
  type LoadErrorInfo,
  type NavigationCallbacks,
  type SecureStorageStore,
  type SelfSdkError,
  SelfVerification,
  type VerificationRequest,
  type VerificationResult,
} from '@selfxyz/rn-sdk';

import {
  captureWebViewLoadDiagnostic,
  clearReferenceTag,
  setReferenceTag,
} from '@/config/sentry';
import type { RootStackParamList } from '@/navigation';
import { selfClientDocumentsAdapter } from '@/providers/passportDataProvider';
import { createWebViewSecureStorageAdapter } from '@/providers/webViewSecureStorageAdapter';
import {
  WebViewErrorOverlay,
  WebViewLoadingOverlay,
} from '@/screens/dev/WebViewHostOverlays';
import { trackEvent, trackNfcEvent } from '@/services/analytics';

const WEBVIEW_DEV_URL_ENV = process.env.WEBVIEW_DEV_URL;

const WebViewHostScreen: React.FC = () => {
  const navigation =
    useNavigation() as NativeStackScreenProps<RootStackParamList>['navigation'];
  const route = useRoute<RouteProp<RootStackParamList, 'WebViewHost'>>();
  const selfClient = useSelfClient();
  const request = useMemo<VerificationRequest>(
    () => (route.params?.request ?? {}) as VerificationRequest,
    [route.params?.request],
  );

  const resultEmittedRef = useRef(false);

  const bundleRootUri = useMemo(() => {
    if (Platform.OS !== 'ios') return undefined;
    try {
      return Paths.bundle.uri;
    } catch {
      return undefined;
    }
  }, []);

  const analytics = useMemo<AnalyticsSink>(
    () => ({
      trackEvent: (name, properties) => trackEvent(name, properties),
      trackNfcEvent: (name, properties) => trackNfcEvent(name, properties),
    }),
    [],
  );

  const navigationCallbacks = useMemo<NavigationCallbacks>(
    () => ({
      onGoBack: () => {
        if (navigation.canGoBack()) {
          navigation.goBack();
          return true;
        }
        return false;
      },
    }),
    [navigation],
  );

  const documents = useMemo<DocumentsStore>(
    () => ({
      loadCatalog: () => selfClientDocumentsAdapter.loadDocumentCatalog(),
      saveCatalog: catalog =>
        selfClientDocumentsAdapter.saveDocumentCatalog(catalog as never),
      loadById: id => selfClientDocumentsAdapter.loadDocumentById(id),
      save: (id, data) =>
        selfClientDocumentsAdapter.saveDocument(id, data as never),
      delete: id => selfClientDocumentsAdapter.deleteDocument(id),
    }),
    [],
  );

  // Host-side translating store: the WebView reads/writes the user's existing
  // legacy keychain (identity + documents) instead of a separate self_sdk_* store.
  const secureStorage = useMemo<SecureStorageStore>(
    () => createWebViewSecureStorageAdapter(),
    [],
  );

  // The host owns the relayer socket (opened in deeplinks via startAppListener).
  // The WebView's proving machine can't own it, so it hands its terminal result
  // back over the bridge (lifecycle.setResult) and the host emits to the relayer,
  // which is what notifies the requesting website.
  const emitRelayerResult = useCallback(
    (proofVerified: boolean, error?: SelfSdkError) => {
      // Emit exactly once. The WebView can hand back its terminal result twice
      // (PROVING-TERMINAL setResult and the result-screen Continue button race),
      // so guard here to keep handleProofResult idempotent. Emit is decoupled
      // from navigation: dismiss/cancel drives goBack, not this path.
      if (resultEmittedRef.current) {
        return;
      }
      const selfAppState = selfClient.getSelfAppState();
      // Only emit while the socket still tracks this request's session, so a
      // stale/reused socket never notifies the wrong website.
      if (
        request.verificationId &&
        selfAppState.sessionId &&
        selfAppState.sessionId !== request.verificationId
      ) {
        trackEvent('webview_relayer_session_mismatch', {
          request_session_match: false,
        });
        return;
      }
      resultEmittedRef.current = true;
      selfAppState.handleProofResult(
        proofVerified,
        error?.code,
        error?.message,
      );
    },
    [request.verificationId, selfClient],
  );

  // Emit-vs-navigation split: success/failure only emit the terminal result to
  // the relayer (fired from the WebView's lifecycle.setResult), leaving the
  // in-WebView result screen visible. Navigation happens solely on dismiss →
  // onCancelled, which the result-screen Continue button triggers via
  // lifecycle.dismiss after setResult.
  const handleSuccess = useCallback(
    (_result: VerificationResult) => {
      emitRelayerResult(true);
    },
    [emitRelayerResult],
  );

  const handleFailure = useCallback(
    (error: SelfSdkError) => {
      emitRelayerResult(false, error);
    },
    [emitRelayerResult],
  );

  const handleCancelled = useCallback(() => {
    navigation.goBack();
  }, [navigation]);

  // Tear down the relayer socket when the host leaves so it isn't orphaned,
  // but only for a truly abandoned session. Two guards protect live sockets:
  useEffect(
    () => () => {
      const selfAppState = selfClient.getSelfAppState();
      // Never tear down a socket a newer deeplink re-pointed to another session.
      if (
        request.verificationId &&
        selfAppState.sessionId &&
        selfAppState.sessionId !== request.verificationId
      ) {
        return;
      }
      // A terminal result was handed to the relayer: leave the socket so
      // socket.io can flush a buffered emit after a transient reconnect (the
      // relay server closes the session on receipt).
      if (resultEmittedRef.current) {
        return;
      }
      selfAppState.cleanSelfApp();
    },
    [selfClient, request.verificationId],
  );

  const handleLoadDiagnostic = useCallback((event: LoadDiagnosticEvent) => {
    captureWebViewLoadDiagnostic(event.kind, event.source, event.detail);
  }, []);

  const renderLoading = useCallback(
    (stage: 'loading' | 'slow') => <WebViewLoadingOverlay stage={stage} />,
    [],
  );

  const renderError = useCallback(
    (info: LoadErrorInfo) => <WebViewErrorOverlay info={info} />,
    [],
  );

  const handleReferenceId = useCallback(
    (referenceId: string) => {
      setReferenceTag(referenceId, request.verificationId);
    },
    [request.verificationId],
  );
  useEffect(() => () => clearReferenceTag(), []);

  return (
    <View
      testID="webview-host-root"
      style={{ flex: 1, backgroundColor: '#000' }}
    >
      <SelfVerification
        request={request}
        mode="self-app"
        onSuccess={handleSuccess}
        onFailure={handleFailure}
        onCancelled={handleCancelled}
        onReferenceId={handleReferenceId}
        debug={__DEV__}
        devServerUrl={__DEV__ ? WEBVIEW_DEV_URL_ENV : undefined}
        bundleRootUri={bundleRootUri}
        analytics={analytics}
        navigation={navigationCallbacks}
        documents={documents}
        secureStorage={secureStorage}
        onLoadDiagnostic={handleLoadDiagnostic}
        renderLoading={renderLoading}
        renderError={renderError}
      />
    </View>
  );
};

export default WebViewHostScreen;
