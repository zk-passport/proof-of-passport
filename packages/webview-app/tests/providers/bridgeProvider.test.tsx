// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// @vitest-environment jsdom

import type React from 'react';
import { StrictMode } from 'react';
import { afterEach, describe, expect, it } from 'vitest';

import { WebViewBridge } from '@selfxyz/webview-bridge';

import { BridgeProvider, resetSharedBridgeForTests, useBridge } from '../../src/providers/BridgeProvider';

import { cleanup, render } from '@testing-library/react';

const Probe: React.FC<{ onBridge: (bridge: WebViewBridge) => void }> = ({ onBridge }) => {
  onBridge(useBridge());
  return null;
};

describe('BridgeProvider', () => {
  afterEach(() => {
    cleanup();
    resetSharedBridgeForTests();
    delete (globalThis as { SelfNativeBridge?: unknown }).SelfNativeBridge;
  });

  it('uses the injected bridge without constructing a default that clobbers globalThis.SelfNativeBridge', () => {
    const injected = {} as WebViewBridge;
    const sentinel = {} as WebViewBridge;
    (globalThis as { SelfNativeBridge?: unknown }).SelfNativeBridge = sentinel;

    let resolved: WebViewBridge | undefined;
    render(
      <BridgeProvider bridge={injected}>
        <Probe onBridge={b => (resolved = b)} />
      </BridgeProvider>,
    );

    expect(resolved).toBe(injected);
    // No default WebViewBridge was constructed, so the global is untouched.
    expect((globalThis as { SelfNativeBridge?: unknown }).SelfNativeBridge).toBe(sentinel);
  });

  it('constructs a default bridge when none is injected', () => {
    let resolved: WebViewBridge | undefined;
    render(
      <BridgeProvider>
        <Probe onBridge={b => (resolved = b)} />
      </BridgeProvider>,
    );

    expect(resolved).toBeInstanceOf(WebViewBridge);
    expect((globalThis as { SelfNativeBridge?: unknown }).SelfNativeBridge).toBe(resolved);
  });

  it('resolves to the same singleton across separate default renders (StrictMode-safe)', () => {
    // The singleton is the whole point of the fix: native only calls back into the one
    // globalThis.SelfNativeBridge, so every consumer must hold that same instance. Under
    // StrictMode the useMemo factory double-invokes, and a second mount re-runs it — all
    // must yield one bridge, or native responses/events would miss the live instance.
    const instances = new Set<WebViewBridge>();
    const Collect: React.FC = () => {
      instances.add(useBridge());
      return null;
    };

    render(
      <StrictMode>
        <BridgeProvider>
          <Collect />
        </BridgeProvider>
      </StrictMode>,
    );
    cleanup();
    render(
      <StrictMode>
        <BridgeProvider>
          <Collect />
        </BridgeProvider>
      </StrictMode>,
    );

    expect(instances.size).toBe(1);
    expect([...instances][0]).toBeInstanceOf(WebViewBridge);
  });
});
