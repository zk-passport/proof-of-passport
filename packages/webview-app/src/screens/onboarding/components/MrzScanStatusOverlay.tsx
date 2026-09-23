// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type React from 'react';
import { useEffect, useState } from 'react';

import type { WebViewBridge } from '@selfxyz/webview-bridge';

type ScanVariant = 'passport' | 'document';

interface ScanProgress {
  state?: string;
  message?: string;
}

// Native pushes both `state` (machine-readable) and `message` (human-readable); we
// prefer `message`. These are the fallbacks used when only `state` arrives.
const STATE_FALLBACK: Record<string, Record<ScanVariant, string>> = {
  no_text: {
    passport: 'Point your camera at the photo page of your passport',
    document: 'Point your camera at the data page of your ID',
  },
  text_detected: { passport: 'Hold steady…', document: 'Hold steady…' },
  one_mrz_line: { passport: 'Almost there — keep holding steady', document: 'Almost there — keep holding steady' },
  mrz_detected: { passport: 'Got it!', document: 'Got it!' },
};

const OPENING: Record<ScanVariant, string> = {
  passport: 'Opening the passport scanner…',
  document: 'Opening the document scanner…',
};

const overlayStyle: React.CSSProperties = {
  position: 'absolute',
  insetInline: 0,
  bottom: 0,
  display: 'flex',
  justifyContent: 'center',
  padding: '24px 16px calc(env(safe-area-inset-bottom, 0px) + 32px)',
  pointerEvents: 'none',
};

const pillStyle: React.CSSProperties = {
  maxWidth: '88%',
  borderRadius: 999,
  background: 'rgba(0, 0, 0, 0.72)',
  color: '#ffffff',
  padding: '10px 18px',
  fontSize: 15,
  lineHeight: 1.3,
  fontWeight: 500,
  textAlign: 'center',
};

/**
 * Status feedback shown over the (intentionally black) viewfinder while native CameraX
 * owns the camera for an MRZ scan. Renders only when native owns the camera; in
 * dev/browser-host the web owns the camera and shows a live preview, so an opaque
 * overlay would just cover it.
 */
export const MrzScanStatusOverlay: React.FC<{ bridge: WebViewBridge; variant: ScanVariant }> = ({
  bridge,
  variant,
}) => {
  const nativeScan = bridge.isConnected && !bridge.usesBrowserHostTransport;
  const [message, setMessage] = useState<string>(OPENING[variant]);

  useEffect(() => {
    if (!nativeScan) return;
    return bridge.on('camera', 'scanProgress', data => {
      const progress = (data ?? {}) as ScanProgress;
      setMessage(
        progress.message ??
          (progress.state ? STATE_FALLBACK[progress.state]?.[variant] : undefined) ??
          OPENING[variant],
      );
    });
  }, [bridge, nativeScan, variant]);

  // Native CameraX owns the camera, so euclid's own <video> stays black. Report where
  // euclid's scan window sits (its <video>'s box) to native, in physical px, so the
  // native preview can be positioned to fill exactly that box. Re-reports on layout
  // settle / resize so it stays aligned. If no measurable box appears within ~1s,
  // falls back to a full-viewport rect — a missing rect must never mean no preview.
  useEffect(() => {
    if (!nativeScan) return;

    const dpr = () => window.devicePixelRatio || 1;
    // `scale` lets native detect visual-viewport zoom, where css×dpr misplaces the rect.
    const fire = (left: number, top: number, width: number, height: number) => {
      bridge.fire('camera', 'setPreviewRect', {
        left: Math.round(left * dpr()),
        top: Math.round(top * dpr()),
        width: Math.round(width * dpr()),
        height: Math.round(height * dpr()),
        dpr: dpr(),
        scale: window.visualViewport?.scale ?? 1,
      });
    };

    const report = () => {
      const box = document.querySelector('video')?.parentElement;
      if (!box) return false;
      const r = box.getBoundingClientRect();
      if (r.width <= 0 || r.height <= 0) return false;
      fire(r.left, r.top, r.width, r.height);
      return true;
    };

    let raf = 0;
    let observer: ResizeObserver | null = null;
    const timers: number[] = [];
    let cancelled = false;

    const fallback = window.setTimeout(() => {
      if (!report()) fire(0, 0, window.innerWidth, window.innerHeight);
    }, 1000);

    const waitForBox = () => {
      if (cancelled) return;
      const box = document.querySelector('video')?.parentElement;
      if (box) {
        report();
        // Catch layout settling (fonts/insets) shortly after mount.
        [120, 350, 800].forEach(ms => timers.push(window.setTimeout(report, ms)));
        if (typeof ResizeObserver !== 'undefined') {
          observer = new ResizeObserver(report);
          observer.observe(box);
        }
      } else {
        raf = window.requestAnimationFrame(waitForBox);
      }
    };
    waitForBox();
    window.addEventListener('resize', report);

    return () => {
      cancelled = true;
      window.cancelAnimationFrame(raf);
      window.clearTimeout(fallback);
      timers.forEach(window.clearTimeout);
      observer?.disconnect();
      window.removeEventListener('resize', report);
    };
  }, [bridge, nativeScan]);

  if (!nativeScan) return null;

  return (
    <div role="status" aria-live="polite" style={overlayStyle}>
      <span style={pillStyle}>{message}</span>
    </div>
  );
};
