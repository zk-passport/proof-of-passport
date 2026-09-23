// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type { WebViewBridge } from '../bridge';

// A native stall must surface as an error the UI can react to, not an
// indefinitely-pending promise over a black viewfinder.
const MRZ_SCAN_TIMEOUT_MS = 120_000;

export interface BridgeCameraAdapter {
  scanMRZ(params?: MrzScanParams): Promise<MrzScanResult>;
  isAvailable(): Promise<boolean>;
}

export interface MrzScanParams {
  documentType?: string;
  countryCode?: string;
  /**
   * Web viewfinder rect (physical px, viewport-relative). When present, the native scanner
   * sizes its preview overlay to this box (parity with the KMP embedded preview).
   */
  scanRect?: { x: number; y: number; width: number; height: number };
  [key: string]: unknown;
}

export interface MrzScanResult {
  documentNumber?: string;
  dateOfBirth?: string;
  dateOfExpiry?: string;
}

export function bridgeCameraAdapter(bridge: WebViewBridge): BridgeCameraAdapter {
  return {
    async scanMRZ(params?: MrzScanParams): Promise<MrzScanResult> {
      // Native handler parses the MRZ JSON string into a JsonElement,
      // which arrives as an object with documentNumber, dateOfBirth, dateOfExpiry.
      try {
        return await bridge.request<MrzScanResult>('camera', 'scanMRZ', params ?? {}, MRZ_SCAN_TIMEOUT_MS);
      } catch (err) {
        // A dead request must not orphan the native scan: the camera would keep
        // streaming (covering the WebView) and its eventual result would be
        // discarded as "No pending request". stopCamera is idempotent native-side.
        bridge.fire('camera', 'stopCamera', {});
        throw err;
      }
    },

    async isAvailable(): Promise<boolean> {
      // Native handler returns JsonPrimitive(true/false).
      return bridge.request<boolean>('camera', 'isAvailable', {});
    },
  };
}
