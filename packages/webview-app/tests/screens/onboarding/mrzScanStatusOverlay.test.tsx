// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// @vitest-environment jsdom

import { afterEach, describe, expect, it } from 'vitest';

import type { NativeTransport } from '@selfxyz/webview-bridge';
import { WebViewBridge } from '@selfxyz/webview-bridge';
import { MockNativeBridge } from '@selfxyz/webview-bridge/mock';

import { MrzScanStatusOverlay } from '../../../src/screens/onboarding/components/MrzScanStatusOverlay';

import { act, cleanup, render } from '@testing-library/react';

// A native transport reports no browser-host kind, so the overlay treats native as the
// camera owner and renders.
function nativeBridge(): { mock: MockNativeBridge; bridge: WebViewBridge } {
  const mock = new MockNativeBridge();
  const bridge = new WebViewBridge({ transport: mock });
  mock.connect(bridge);
  return { mock, bridge };
}

describe('MrzScanStatusOverlay', () => {
  afterEach(() => {
    cleanup();
    delete (globalThis as { SelfNativeBridge?: unknown }).SelfNativeBridge;
  });

  it('shows the opening message, then maps scanProgress state to passport wording', () => {
    const { mock, bridge } = nativeBridge();
    const result = render(<MrzScanStatusOverlay bridge={bridge} variant="passport" />);

    expect(result.getByRole('status').textContent).toContain('Opening the passport scanner');

    // state only, no message -> falls back to the variant-specific copy.
    act(() => mock.pushEvent('camera', 'scanProgress', { state: 'no_text' }));
    expect(result.getByRole('status').textContent).toContain('photo page of your passport');

    act(() => mock.pushEvent('camera', 'scanProgress', { state: 'text_detected' }));
    expect(result.getByRole('status').textContent).toContain('Hold steady');
  });

  it('uses document wording for the document variant fallback', () => {
    const { mock, bridge } = nativeBridge();
    const result = render(<MrzScanStatusOverlay bridge={bridge} variant="document" />);

    expect(result.getByRole('status').textContent).toContain('Opening the document scanner');

    act(() => mock.pushEvent('camera', 'scanProgress', { state: 'no_text' }));
    expect(result.getByRole('status').textContent).toContain('data page of your ID');
  });

  it('prefers the human-readable message over the state fallback', () => {
    const { mock, bridge } = nativeBridge();
    const result = render(<MrzScanStatusOverlay bridge={bridge} variant="passport" />);

    act(() => mock.pushEvent('camera', 'scanProgress', { state: 'text_detected', message: 'Reading the MRZ…' }));
    expect(result.getByRole('status').textContent).toBe('Reading the MRZ…');
  });

  it('renders nothing when a browser host owns the camera (dev/browser-host)', () => {
    const transport: NativeTransport = { kind: 'browser-host', postMessage: () => {} };
    const bridge = new WebViewBridge({ transport });
    const result = render(<MrzScanStatusOverlay bridge={bridge} variant="passport" />);

    expect(result.queryByRole('status')).toBeNull();
  });

  it('renders nothing when no native transport is connected', () => {
    // No transport detected under jsdom (no SelfNativeAndroid / webkit / RN / parent host).
    const bridge = new WebViewBridge();
    const result = render(<MrzScanStatusOverlay bridge={bridge} variant="passport" />);

    expect(result.queryByRole('status')).toBeNull();
  });
});
