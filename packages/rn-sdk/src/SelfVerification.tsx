// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import React, {
  useRef,
  useCallback,
  useMemo,
  useState,
  useEffect,
} from 'react';
import {
  View,
  Platform,
  Text,
  TouchableOpacity,
  ActivityIndicator,
  BackHandler,
  type ViewStyle,
} from 'react-native';
import WebView, { type WebViewMessageEvent } from 'react-native-webview';

import { MessageRouter } from './bridge/MessageRouter';
import { KmpBridgeTransport } from './bridge/KmpBridgeTransport';
import { createHandlers } from './handlers';
import type { AnalyticsSink } from './handlers/AnalyticsHandler';
import type { NavigationCallbacks } from './handlers/NavigationHandler';
import type { DocumentsStore } from './handlers/DocumentsHandler';
import type { SecureStorageStore } from './handlers/KeychainHandler';
import type { SelfCryptoModule } from './handlers/CryptoHandler';
import type { OperatingMode } from './handlers/LifecycleHandler';
import { WebViewLoadEvents } from './analytics-events';
import { resolveBundlePath } from './bundlePath';
import { COLORS } from './theme';

// iOS main-bundle path provider for native hosts (KMP, partner wallets) that
// install react-native-fs. The Expo-based Self app instead injects the bundle
// URI via the `bundleRootUri` prop — the SDK must not statically require an
// Expo module, since bundlers (Metro) resolve literal require() at build time
// even inside try/catch, which would break non-Expo hosts.
let rnfsMainBundlePath: unknown;
try {
  rnfsMainBundlePath = require('react-native-fs').MainBundlePath;
} catch {
  // react-native-fs not installed; host may inject bundleRootUri instead.
}

const toFileUri = (path: string) =>
  path.startsWith('file://') ? path : `file://${path}`;

export interface VerificationRequest {
  userId?: string;
  scope?: string;
  disclosures?: string[];
  appName?: string;
  appEndpoint?: string;
  environment?: 'prod' | 'stg';
  endpointType?: 'https' | 'celo' | 'staging_https' | 'staging_celo';
  version?: number;
  chainID?: number;
  verificationId?: string;
  userDefinedData?: string;
  selfDefinedData?: string;
  excludedCountries?: string[];
  proofItems?: string[];
  // Document constraints forwarded to the WebView so its embed fail-closed
  // capability guard (webview-app capabilities.ts) can decide whether a
  // required native module (nfc / mrzCamera) is missing. Dropping these makes
  // that guard a no-op, so they are serialized in buildRequestSearch.
  documentType?: string;
  documentTypes?: string[];
  ids?: string[];
  userIdType?: 'hex' | 'uuid';
  timestamp?: number;
  // Host-minted WebView reference session id. When omitted, SelfVerification
  // mints one per load so it is always present for RN-hosted WebViews.
  referenceId?: string;
}

export interface VerificationResult {
  success: boolean;
  userId?: string;
  verificationId?: string;
  proof?: unknown;
  claims?: Record<string, unknown>;
}

export interface SelfSdkError {
  code: string;
  message: string;
}

/**
 * Why the WebView failed to load. `version_mismatch` covers both a
 * present-but-wrong protocol version (terminal) and a missing/non-numeric one
 * (recoverable) — the diagnostic records the cause; the UX stage records
 * whether retry is offered. Shared, snake_case taxonomy across the diagnostic
 * `kind` and the `renderError` literal.
 */
export type LoadDiagnosticKind = 'timeout' | 'load_error' | 'version_mismatch';

export interface LoadDiagnosticEvent {
  kind: LoadDiagnosticKind;
  source: 'bundle' | 'dev-server';
  detail?: Record<string, unknown>;
}

export interface LoadErrorInfo {
  kind: LoadDiagnosticKind;
  canRetry: boolean;
  onRetry: () => void;
}

export interface SelfVerificationProps {
  request: VerificationRequest;
  onSuccess: (result: VerificationResult) => void;
  onFailure: (error: SelfSdkError) => void;
  onCancelled: () => void;
  debug?: boolean;
  /**
   * Fired once per load with the resolved host-minted reference id (the one
   * passed to the WebView). The host wires this to its Sentry `reference_id`
   * tag so RN-host and WebView events for the same session correlate. rn-sdk
   * stays Sentry-agnostic; tagging lives in the host.
   */
  onReferenceId?: (referenceId: string) => void;
  /**
   * Operating mode signaled to the WebView at boot via lifecycle.getConfig.
   * 'self-app' = persistent UI (Self app). 'embed' = one-shot
   * verification (3rd-party SDK embedders). Default: 'self-app'.
   * See specs/projects/sdk/workstreams/webview-in-app/SPEC-MODES.html.
   */
  mode?: OperatingMode;
  /**
   * When set (and __DEV__ is true), load this URL instead of the bundled
   * asset. Release builds compile the dev path out entirely so this is
   * ignored even if a malicious caller passes it in production.
   */
  devServerUrl?: string;
  /**
   * iOS only: absolute `file://` URI of the native bundle root that contains
   * the embedded `self-wallet/` assets. Expo hosts pass `Paths.bundle.uri`
   * (from expo-file-system); native hosts can omit it and rely on
   * react-native-fs. Ignored on Android (assets load from `android_asset`).
   * Without either provider on iOS the load fails, so one must be present.
   */
  bundleRootUri?: string;
  /**
   * Bridge handler injection points. Each is optional; omitting leaves the
   * handler with default behavior (analytics is silent, navigation reports
   * not-handled, documents uses an in-memory store, secureStorage uses
   * react-native-keychain, crypto requires the native SelfCrypto module).
   */
  analytics?: AnalyticsSink;
  navigation?: NavigationCallbacks;
  documents?: DocumentsStore;
  secureStorage?: SecureStorageStore;
  crypto?: SelfCryptoModule;
  /**
   * Prototype flag — when true, route `secureStorage.*` bridge messages
   * through the KMP-backed native module (SelfBridge) instead of the local
   * TS KeychainHandler. All other domains continue to use the existing TS
   * handlers. See specs/projects/sdk/workstreams/webview-in-app/plans/
   * PATH-A-rn-wraps-kmp.html. Default: false.
   */
  useKmpBridge?: boolean;
  /**
   * Time in ms before the loading splash transitions to a "still loading"
   * state with a manual retry. Defaults to 3000ms.
   */
  spinnerTimeoutMs?: number;
  /**
   * Time in ms before the loading splash treats the WebView as failed to
   * load and surfaces a recoverable error. Defaults to 10000ms.
   */
  loadTimeoutMs?: number;
  /**
   * Optional error-telemetry reporter, injected (never imported) so rn-sdk
   * stays free of @sentry/react-native. The host maps each diagnostic to its
   * own Sentry instance. Separate from `analytics` — diagnostics are error
   * telemetry, analytics is the product funnel.
   */
  onLoadDiagnostic?: (event: LoadDiagnosticEvent) => void;
  /**
   * Consumer-supplied loading UI. When omitted, a built-in default backed by
   * the local palette renders.
   */
  renderLoading?: (stage: 'loading' | 'slow') => React.ReactNode;
  /**
   * Consumer-supplied error UI. `canRetry` is false for a terminal version
   * mismatch (the frozen bundle would mismatch identically on reload), true
   * for recoverable failures. When omitted, a built-in default renders.
   */
  renderError?: (info: LoadErrorInfo) => React.ReactNode;
  style?: ViewStyle;
}

type LoadStage = 'loading' | 'slow' | 'failed' | 'ready' | 'version_mismatch';

const DEFAULT_SPINNER_TIMEOUT_MS = 3000;
const DEFAULT_LOAD_TIMEOUT_MS = 10_000;

function isSecureStorageRequest(raw: string): boolean {
  try {
    const parsed = JSON.parse(raw) as { type?: string; domain?: string };
    return parsed.type === 'request' && parsed.domain === 'secureStorage';
  } catch {
    return false;
  }
}

function makeReferenceId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `corr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function buildRequestSearch(
  request: VerificationRequest,
  referenceId: string,
): string {
  const params = new URLSearchParams();
  const set = (key: string, value: string | number | undefined) => {
    if (value === undefined || value === null) return;
    const str = String(value);
    if (!str) return;
    params.set(key, str);
  };
  set('referenceId', referenceId);
  set('userId', request.userId);
  set('scope', request.scope);
  if (request.disclosures && request.disclosures.length > 0) {
    params.set('disclosures', request.disclosures.join(','));
  }
  if (request.excludedCountries && request.excludedCountries.length > 0) {
    params.set('excludedCountries', request.excludedCountries.join(','));
  }
  if (request.proofItems && request.proofItems.length > 0) {
    params.set('proofItems', request.proofItems.join(','));
  }
  set('documentType', request.documentType);
  if (request.documentTypes && request.documentTypes.length > 0) {
    params.set('documentTypes', request.documentTypes.join(','));
  }
  if (request.ids && request.ids.length > 0) {
    params.set('ids', request.ids.join(','));
  }
  set('appName', request.appName);
  set('appEndpoint', request.appEndpoint);
  set('environment', request.environment);
  set('endpointType', request.endpointType);
  set('version', request.version);
  set('chainID', request.chainID);
  set('verificationId', request.verificationId);
  set('userDefinedData', request.userDefinedData);
  set('selfDefinedData', request.selfDefinedData);
  set('userIdType', request.userIdType);
  set('timestamp', request.timestamp);
  return params.toString();
}

export const SelfVerification: React.FC<SelfVerificationProps> = ({
  request,
  onSuccess,
  onFailure,
  onCancelled,
  debug = false,
  onReferenceId,
  mode,
  devServerUrl,
  bundleRootUri,
  analytics,
  navigation,
  documents,
  secureStorage,
  crypto,
  useKmpBridge = false,
  spinnerTimeoutMs = DEFAULT_SPINNER_TIMEOUT_MS,
  loadTimeoutMs = DEFAULT_LOAD_TIMEOUT_MS,
  onLoadDiagnostic,
  renderLoading,
  renderError,
  style,
}) => {
  const webViewRef = useRef<WebView>(null);
  const [loadStage, setLoadStage] = useState<LoadStage>('loading');
  const [errorKind, setErrorKind] = useState<LoadDiagnosticKind | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  // Resolve the host-minted reference id: a supplied id wins; otherwise mint one
  // and cache it keyed by request identity so it stays stable across re-renders
  // of the same request but re-mints for a new request — distinct verifications
  // never share a reference_id. A blank supplied id is treated as absent.
  const providedReferenceId = request.referenceId?.trim() || undefined;
  const requestIdentity = useMemo(() => {
    const { referenceId: _omitted, ...rest } = request;
    return JSON.stringify(rest);
  }, [request]);
  const generatedReferenceRef = useRef<{ key: string; id: string } | null>(
    null,
  );
  let referenceId = providedReferenceId;
  if (!referenceId) {
    if (generatedReferenceRef.current?.key !== requestIdentity) {
      generatedReferenceRef.current = {
        key: requestIdentity,
        id: makeReferenceId(),
      };
    }
    referenceId = generatedReferenceRef.current.id;
  }
  const onReferenceIdRef = useRef(onReferenceId);
  useEffect(() => {
    onReferenceIdRef.current = onReferenceId;
  });
  useEffect(() => {
    onReferenceIdRef.current?.(referenceId);
  }, [referenceId]);

  const isDevServer = __DEV__ && Boolean(devServerUrl);
  const diagnosticSource: LoadDiagnosticEvent['source'] = isDevServer
    ? 'dev-server'
    : 'bundle';

  // Mirror loadStage into a ref so the fail/diagnostic helpers can read the
  // current stage synchronously (avoids stale closures across timers and
  // WebView events) and guard against regressing a terminal/ready stage.
  const loadStageRef = useRef<LoadStage>('loading');
  useEffect(() => {
    loadStageRef.current = loadStage;
  }, [loadStage]);

  const onLoadDiagnosticRef = useRef(onLoadDiagnostic);
  const analyticsRef = useRef(analytics);
  const recoveryPendingRef = useRef(false);
  useEffect(() => {
    onLoadDiagnosticRef.current = onLoadDiagnostic;
    analyticsRef.current = analytics;
  }, [onLoadDiagnostic, analytics]);

  // Funnel analytics are fire-and-forget: a throwing or slow sink must never
  // block or break the load/error UI.
  const trackFunnel = useCallback(
    (name: string, properties: Record<string, unknown>) => {
      try {
        analyticsRef.current?.trackEvent(name, properties);
      } catch {
        /* swallow — analytics must not affect the load UI */
      }
    },
    [],
  );

  // Drive a failure transition once: report the Sentry diagnostic and the
  // analytics funnel event, then move the stage. A terminal version mismatch
  // may upgrade a prior recoverable `failed`; nothing regresses `ready`.
  const reportFailure = useCallback(
    (
      kind: LoadDiagnosticKind,
      stage: 'failed' | 'version_mismatch',
      detail?: Record<string, unknown>,
      options?: { force?: boolean },
    ) => {
      const prev = loadStageRef.current;
      if (
        (prev === 'ready' && !options?.force) ||
        prev === 'version_mismatch'
      ) {
        return;
      }
      if (prev === 'failed' && stage !== 'version_mismatch') return;

      loadStageRef.current = stage;
      setLoadStage(stage);
      setErrorKind(kind);

      try {
        onLoadDiagnosticRef.current?.({
          kind,
          source: diagnosticSource,
          detail,
        });
      } catch {
        /* swallow — diagnostics must not affect the load UI */
      }

      if (kind === 'version_mismatch') {
        trackFunnel(WebViewLoadEvents.VERSION_MISMATCH, {
          source: diagnosticSource,
          recoverable: stage === 'failed',
        });
      } else {
        trackFunnel(WebViewLoadEvents.LOAD_FAILED, {
          kind,
          source: diagnosticSource,
        });
      }
    },
    [diagnosticSource, trackFunnel],
  );

  // Track WebView readiness via the lifecycle.ready bridge message. A ready
  // that lands after a recoverable failure (retry succeeded) is a funnel
  // recovery.
  const handleReady = useCallback(() => {
    const prev = loadStageRef.current;
    if (prev === 'version_mismatch') return;
    if (prev === 'failed' && !recoveryPendingRef.current) return;

    if (recoveryPendingRef.current) {
      trackFunnel(WebViewLoadEvents.LOAD_RECOVERED, {
        source: diagnosticSource,
      });
    }
    recoveryPendingRef.current = false;
    loadStageRef.current = 'ready';
    setLoadStage('ready');
  }, [diagnosticSource, trackFunnel]);

  const handleVersionMismatch = useCallback(
    ({ received, expected }: { received: unknown; expected: number }) => {
      if (typeof received === 'number') {
        reportFailure('version_mismatch', 'version_mismatch', {
          received,
          expected,
          recoverable: false,
        });
      } else {
        reportFailure('version_mismatch', 'failed', {
          received,
          expected,
          recoverable: true,
        });
      }
    },
    [reportFailure],
  );

  // We extend onGoBack so React Native's BackHandler can route through it.
  const navigationWithBack = useMemo<NavigationCallbacks>(() => {
    return {
      onGoBack: navigation?.onGoBack,
      onGoTo: navigation?.onGoTo,
    };
  }, [navigation]);

  const router = useMemo(
    () =>
      new MessageRouter({
        sendToWebView: (js: string) => {
          webViewRef.current?.injectJavaScript(js);
        },
        debug,
        onVersionMismatch: handleVersionMismatch,
      }),
    [debug, handleVersionMismatch],
  );

  const kmpTransport = useMemo<KmpBridgeTransport | undefined>(() => {
    if (!useKmpBridge) return undefined;
    return new KmpBridgeTransport({
      inject: (js: string) => {
        webViewRef.current?.injectJavaScript(js);
      },
      debug,
    });
  }, [useKmpBridge, debug]);

  useEffect(() => {
    return () => kmpTransport?.dispose();
  }, [kmpTransport]);

  // Wrap lifecycle ready so the loading splash dismisses.
  const wrappedOnSuccess = useCallback(
    (result: VerificationResult) => {
      onSuccess(result);
    },
    [onSuccess],
  );

  useEffect(() => {
    const handlers = createHandlers({
      request,
      onSuccess: wrappedOnSuccess,
      onFailure,
      onCancelled,
      debug,
      router,
      analytics,
      navigation: navigationWithBack,
      documents,
      secureStorage,
      crypto,
      mode,
      referenceId,
    });
    // Wrap the lifecycle ready handler to mark the splash dismissed.
    const lifecycle = handlers.find(h => h.domain === 'lifecycle');
    if (lifecycle) {
      const originalHandle = lifecycle.handle.bind(lifecycle);
      lifecycle.handle = async (method, params) => {
        if (method === 'ready') {
          handleReady();
        }
        return originalHandle(method, params);
      };
    }
    handlers.forEach(h => router.register(h));
  }, [
    request,
    wrappedOnSuccess,
    onFailure,
    onCancelled,
    debug,
    router,
    analytics,
    navigationWithBack,
    documents,
    secureStorage,
    crypto,
    mode,
    referenceId,
    handleReady,
  ]);

  // Hardware-back routing on Android: ask the WebView first via the bridge;
  // if the WebView's navigation handler claims it (returns handled=true), we
  // do nothing here. If not, the BackHandler falls through to the host
  // navigator's default behavior.
  useEffect(() => {
    if (Platform.OS !== 'android') return undefined;
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      router.pushEvent('navigation', 'back', {});
      // Always claim the back press — the WebView decides what to do.
      return true;
    });
    return () => sub.remove();
  }, [router]);

  // Loading state machine: spinner → slow → failed. `version_mismatch` is
  // terminal — do not arm timers against it.
  useEffect(() => {
    if (loadStage === 'ready' || loadStage === 'version_mismatch') {
      return undefined;
    }
    const slowTimer = setTimeout(() => {
      setLoadStage(stage => (stage === 'loading' ? 'slow' : stage));
    }, spinnerTimeoutMs);
    const failTimer = setTimeout(() => {
      reportFailure('timeout', 'failed');
    }, loadTimeoutMs);
    return () => {
      clearTimeout(slowTimer);
      clearTimeout(failTimer);
    };
  }, [loadStage, reloadKey, spinnerTimeoutMs, loadTimeoutMs, reportFailure]);

  const onMessage = useCallback(
    (event: WebViewMessageEvent) => {
      const raw = event.nativeEvent.data;
      if (kmpTransport?.isAvailable() && isSecureStorageRequest(raw)) {
        kmpTransport.dispatch(raw);
        return;
      }
      router.onMessageReceived(raw);
    },
    [router, kmpTransport],
  );

  const requestSearch = useMemo(
    () => buildRequestSearch(request, referenceId),
    [request, referenceId],
  );

  const source = useMemo(() => {
    if (isDevServer && devServerUrl) {
      const sep = devServerUrl.includes('?') ? '&' : '?';
      const uri = requestSearch
        ? `${devServerUrl}${sep}${requestSearch}`
        : devServerUrl;
      return { uri };
    }
    const appendSearch = (uri: string) =>
      requestSearch ? `${uri}?${requestSearch}` : uri;
    const mainBundlePath = resolveBundlePath(rnfsMainBundlePath, bundleRootUri);
    return Platform.select({
      android: {
        uri: appendSearch('file:///android_asset/self-wallet/index.html'),
      },
      ios: {
        uri: appendSearch(
          mainBundlePath
            ? toFileUri(`${mainBundlePath}/self-wallet/index.html`)
            : 'self-wallet/index.html',
        ),
      },
    });
  }, [isDevServer, devServerUrl, requestSearch, bundleRootUri]);

  const retry = useCallback(() => {
    recoveryPendingRef.current = loadStageRef.current === 'failed';
    loadStageRef.current = 'loading';
    setErrorKind(null);
    setLoadStage('loading');
    setReloadKey(k => k + 1);
    webViewRef.current?.reload();
  }, []);

  // A hard WebView load error (missing/corrupt bundle, HTTP error) fails fast
  // instead of waiting for the 10s timeout. Guarded so a late event after
  // `ready` does not regress the stage.
  const handleWebViewError = useCallback(
    (detail: Record<string, unknown>) => {
      reportFailure('load_error', 'failed', detail);
    },
    [reportFailure],
  );

  const handleRenderProcessGone = useCallback(
    (detail: Record<string, unknown>) => {
      reportFailure('load_error', 'failed', detail, { force: true });
    },
    [reportFailure],
  );

  const overlay = useMemo<React.ReactNode>(() => {
    if (loadStage === 'ready') return null;
    if (loadStage === 'loading' || loadStage === 'slow') {
      return renderLoading ? (
        renderLoading(loadStage)
      ) : (
        <DefaultLoadingOverlay stage={loadStage} />
      );
    }
    const info: LoadErrorInfo =
      loadStage === 'version_mismatch'
        ? { kind: 'version_mismatch', canRetry: false, onRetry: retry }
        : { kind: errorKind ?? 'load_error', canRetry: true, onRetry: retry };
    return renderError ? (
      renderError(info)
    ) : (
      <DefaultErrorOverlay info={info} />
    );
  }, [loadStage, errorKind, renderLoading, renderError, retry]);

  return (
    <View style={[{ flex: 1, backgroundColor: COLORS.bg }, style]}>
      <WebView
        key={reloadKey}
        ref={webViewRef}
        source={source!}
        onMessage={onMessage}
        onError={({ nativeEvent }) =>
          handleWebViewError({
            phase: 'onError',
            code: nativeEvent.code,
            description: nativeEvent.description,
          })
        }
        onHttpError={({ nativeEvent }) =>
          handleWebViewError({
            phase: 'onHttpError',
            statusCode: nativeEvent.statusCode,
            description: nativeEvent.description,
          })
        }
        onRenderProcessGone={({ nativeEvent }) =>
          handleRenderProcessGone({
            phase: 'onRenderProcessGone',
            didCrash: nativeEvent.didCrash,
          })
        }
        javaScriptEnabled
        domStorageEnabled
        allowFileAccess
        allowFileAccessFromFileURLs
        allowUniversalAccessFromFileURLs
        mediaPlaybackRequiresUserAction={false}
        originWhitelist={['*']}
        style={{ flex: 1, opacity: loadStage === 'ready' ? 1 : 0 }}
      />
      {overlay}
    </View>
  );
};

const overlayContainerStyle: ViewStyle = {
  position: 'absolute',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: COLORS.bg,
  alignItems: 'center',
  justifyContent: 'center',
};

const DefaultLoadingOverlay: React.FC<{ stage: 'loading' | 'slow' }> = ({
  stage,
}) => (
  <View style={overlayContainerStyle}>
    <ActivityIndicator size="large" color={COLORS.fg} />
    {stage === 'slow' ? (
      <Text style={{ color: COLORS.fg, marginTop: 16 }}>Still loading…</Text>
    ) : null}
  </View>
);

const DefaultErrorOverlay: React.FC<{ info: LoadErrorInfo }> = ({ info }) => (
  <View style={overlayContainerStyle}>
    <Text style={{ color: COLORS.fg, marginTop: 16, textAlign: 'center' }}>
      {info.kind === 'version_mismatch'
        ? 'Please update Self app'
        : "Couldn't load Self."}
    </Text>
    {info.canRetry ? (
      <TouchableOpacity
        onPress={info.onRetry}
        accessibilityRole="button"
        style={{
          marginTop: 24,
          paddingHorizontal: 24,
          paddingVertical: 12,
          borderColor: COLORS.fg,
          borderWidth: 1,
          borderRadius: 8,
        }}
      >
        <Text style={{ color: COLORS.fg }}>Retry</Text>
      </TouchableOpacity>
    ) : null}
  </View>
);
