// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import React from 'react';
import { MemoryRouter, useLocation } from 'react-router-dom';

import type { BridgeDomain } from '@selfxyz/webview-bridge';
import { WebViewBridge } from '@selfxyz/webview-bridge';
import { MockNativeBridge } from '@selfxyz/webview-bridge/mock';

import { App } from '../../src/App';
import { BridgeProvider } from '../../src/providers/BridgeProvider';

import type { RenderResult } from '@testing-library/react';
import { render } from '@testing-library/react';

type InitialEntry = string | { pathname: string; search?: string; state?: unknown };

export interface HostConfig {
  mode?: 'self-app' | 'embed';
  verificationRequest?: { userId?: string; scope?: string; [key: string]: unknown } | null;
  referenceId?: string;
  [key: string]: unknown;
}

export interface RenderWithBridgeOptions {
  initialEntries: InitialEntry[];
  // Host config returned from lifecycle.getConfig. Defaults to self-app mode.
  config?: HostConfig;
  // Seed values for the in-memory secure storage map (key -> string value).
  storage?: Record<string, string>;
  // Caller hook to register flow-specific handlers (camera/scanMRZ, nfc/scanPassport,
  // etc.) or to override any baseline handler. Runs after defaults are registered.
  setupHandlers?: (mock: MockNativeBridge) => void;
  // Wrap the tree in <React.StrictMode> so effects run setup→cleanup→setup (dev
  // behavior). Reproduces the interleaved-cleanup class of bugs in start-once effects.
  strictMode?: boolean;
}

export interface RenderWithBridgeResult extends RenderResult {
  mock: MockNativeBridge;
  bridge: WebViewBridge;
  storage: Map<string, string>;
  // Re-render the same tree in place (preserves the router history and the bridge).
  // Used to reproduce spurious mid-effect re-renders.
  forceRerender: () => void;
}

const LocationProbe: React.FC = () => {
  const location = useLocation();
  return <div data-testid="location-probe" data-pathname={location.pathname} />;
};

export function currentPath(result: RenderWithBridgeResult): string {
  return result.getByTestId('location-probe').getAttribute('data-pathname') ?? '';
}

/**
 * Mounts the real webview-app (route table + provider stack) over a
 * MockNativeBridge-backed WebViewBridge, at a chosen router entry. Tests drive
 * real routing and real bridge round-trips; only the native side is mocked.
 */
export function renderWithBridge(options: RenderWithBridgeOptions): RenderWithBridgeResult {
  const { initialEntries, config, storage: seed, setupHandlers, strictMode } = options;

  const mock = new MockNativeBridge();
  const storage = new Map<string, string>(Object.entries(seed ?? {}));

  // Awaited boot request: operating mode + reference id.
  mock.handle('lifecycle', 'getConfig', () => ({ mode: 'self-app', ...config }));

  // Awaited / fire-and-forget lifecycle calls made during normal render.
  mock.handleWith('lifecycle', 'ready', {});
  mock.handleWith('lifecycle', 'setResult', {});
  mock.handleWith('lifecycle', 'dismiss', {});
  mock.handleWith('haptic', 'trigger', {});

  // Secure storage backed by an in-memory map. Covers the secret manager,
  // document catalog (self_document_catalog) and document bodies (self_doc_*).
  mock.handle('secureStorage', 'get', params => {
    const key = params.key as string;
    return storage.has(key) ? storage.get(key) : null;
  });
  mock.handle('secureStorage', 'set', params => {
    storage.set(params.key as string, params.value as string);
    return {};
  });
  mock.handle('secureStorage', 'remove', params => {
    storage.delete(params.key as string);
    return {};
  });

  setupHandlers?.(mock);

  const bridge = new WebViewBridge({ transport: mock });
  mock.connect(bridge);

  // Fresh element each call so a rerender doesn't hit React's identical-element bail-out.
  // MemoryRouter keeps its history in an internal ref, so routing survives the rerender.
  const renderTree = () => {
    const tree = (
      <BridgeProvider bridge={bridge}>
        <App
          renderRouter={children => (
            <MemoryRouter initialEntries={initialEntries}>
              {children}
              <LocationProbe />
            </MemoryRouter>
          )}
        />
      </BridgeProvider>
    );
    return strictMode ? <React.StrictMode>{tree}</React.StrictMode> : tree;
  };

  const result = render(renderTree());

  return Object.assign(result, { mock, bridge, storage, forceRerender: () => result.rerender(renderTree()) });
}

export type { BridgeDomain };
