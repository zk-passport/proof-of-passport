// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type React from 'react';
import { useCallback, useEffect, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { EuIdViewfinderScreen } from '@selfxyz/euclid';
import { bridgeCameraAdapter } from '@selfxyz/webview-bridge/adapters';

import { useBridge } from '../../../providers/BridgeProvider';
import { useSelfClient } from '../../../providers/SelfClientProvider';
import type { NavState } from '../../../types/navState';
import { WEB_SAFE_AREA } from '../../../utils/insets';
import { MrzScanStatusOverlay } from '../components/MrzScanStatusOverlay';

// Stable identity for the no-router-state case, so `state` in the scan effect's dep
// array doesn't churn on every render and needlessly re-run the effect.
const EMPTY_STATE: Partial<NavState> = Object.freeze({});

// Module-level so React StrictMode's double-effect in dev shares one native
// scan instead of the first (immediately-cancelled) effect owning the only
// pending promise and dropping its result. `mrzScanClaims` counts live effect
// runs: when it drops to 0 (a real route exit, not a StrictMode remount) the
// scan is invalidated and the native camera stopped.
let activeMrzScan: Promise<Awaited<ReturnType<ReturnType<typeof bridgeCameraAdapter>['scanMRZ']>>> | null = null;
let mrzScanClaims = 0;

export const EuIdViewfinderRoute: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const bridge = useBridge();
  const { analytics, haptic } = useSelfClient();
  const state = useMemo(() => (location.state as Partial<NavState> | null) ?? EMPTY_STATE, [location.state]);
  const cameraAdapter = useMemo(() => bridgeCameraAdapter(bridge), [bridge]);

  useEffect(() => {
    let cancelled = false;
    mrzScanClaims += 1;
    void (async () => {
      if (!activeMrzScan) {
        analytics.trackEvent('eu_id_mrz_scan_started');
        activeMrzScan = cameraAdapter.scanMRZ({ documentType: 'id_card' });
      }
      const scan = activeMrzScan;
      try {
        const mrz = await scan;
        if (activeMrzScan === scan) activeMrzScan = null;
        if (cancelled) return;
        if (!mrz?.documentNumber || !mrz?.dateOfBirth || !mrz?.dateOfExpiry) {
          throw new Error('Incomplete MRZ result');
        }
        analytics.trackEvent('eu_id_mrz_scan_succeeded');
        haptic.trigger('success');
        navigate('/capture/eu-id/nfc-instructions', {
          state: {
            ...state,
            mrz: {
              passportNumber: mrz.documentNumber,
              dateOfBirth: mrz.dateOfBirth,
              dateOfExpiry: mrz.dateOfExpiry,
            },
          },
          replace: true,
        });
      } catch (err) {
        if (activeMrzScan === scan) activeMrzScan = null;
        if (cancelled) return;
        const message = err instanceof Error ? err.message : 'MRZ scan failed';
        analytics.trackEvent('eu_id_mrz_scan_failed', { error: message });
        haptic.trigger('warning');
        navigate('/capture/eu-id/nfc-error', {
          state: { ...state, errorMessage: message, stage: 'mrz' },
          replace: true,
        });
      }
    })();

    return () => {
      cancelled = true;
      mrzScanClaims -= 1;
      // Deferred: a StrictMode remount re-claims synchronously before this
      // runs; only a real route exit leaves the count at 0.
      setTimeout(() => {
        if (mrzScanClaims === 0 && activeMrzScan) {
          activeMrzScan = null;
          void bridge.request('camera', 'stopCamera', {}).catch(() => {});
        }
      }, 0);
    };
  }, [analytics, bridge, cameraAdapter, haptic, navigate, state]);

  const handleBack = useCallback(() => {
    haptic.trigger('selection');
    navigate('/capture/eu-id/back-instructions', { state, replace: true });
  }, [haptic, navigate, state]);

  const onCaptureTips = useCallback(() => {
    haptic.trigger('selection');
    analytics.trackEvent('eu_id_viewfinder_capture_tips');
  }, [analytics, haptic]);

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      <EuIdViewfinderScreen insets={WEB_SAFE_AREA.insets} onClose={handleBack} onCaptureTips={onCaptureTips} />
      <MrzScanStatusOverlay bridge={bridge} variant="document" />
    </div>
  );
};
