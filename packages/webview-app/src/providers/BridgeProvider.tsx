// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type React from 'react';
import { createContext, useContext, useMemo } from 'react';

import { WebViewBridge } from '@selfxyz/webview-bridge';

import { parseBrowserHostTargetOrigin } from '../utils/verificationRequest';

const BridgeContext = createContext<WebViewBridge | null>(null);

// Process-wide singleton. WebViewBridge's constructor registers itself as
// globalThis.SelfNativeBridge, and native only ever calls back into that single global
// (_handleResponse / _handleEvent). If more than one WebViewBridge were constructed —
// React StrictMode double-invokes the useMemo factory in dev, and a memo can be
// recreated — the global would point at one instance while the tree held another.
// Native responses would then miss the live `pending` map ("No pending request for:
// <id>" in logcat) and scanProgress events would dispatch to an instance with no
// listeners (no scan feedback). Building exactly one bridge at module scope keeps the
// global, the pending map, and the event listeners on the same object.
let sharedBridge: WebViewBridge | null = null;

function getSharedBridge(): WebViewBridge {
  if (!sharedBridge) {
    const isDev = import.meta.env.DEV;
    sharedBridge = new WebViewBridge({
      debug: isDev,
      browserHost: {
        targetOrigin:
          parseBrowserHostTargetOrigin(window.location.search, {
            allowWildcard: isDev,
          }) ?? (isDev ? '*' : undefined),
      },
    });
  }
  return sharedBridge;
}

/** Test-only: drop the process-wide bridge so each test starts from a clean slate. */
export function resetSharedBridgeForTests(): void {
  sharedBridge?.destroy();
  sharedBridge = null;
}

export const BridgeProvider: React.FC<{ children: React.ReactNode; bridge?: WebViewBridge }> = ({
  children,
  bridge: injectedBridge,
}) => {
  const defaultBridge = useMemo(() => (injectedBridge ? null : getSharedBridge()), [injectedBridge]);

  return <BridgeContext.Provider value={injectedBridge ?? defaultBridge}>{children}</BridgeContext.Provider>;
};

export function useBridge(): WebViewBridge {
  const bridge = useContext(BridgeContext);
  if (!bridge) {
    throw new Error('useBridge must be used within a BridgeProvider');
  }
  return bridge;
}
