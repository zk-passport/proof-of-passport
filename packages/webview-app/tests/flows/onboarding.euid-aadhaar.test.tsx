// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// @vitest-environment jsdom

import { afterEach, describe, expect, it } from 'vitest';

import { currentPath, renderWithBridge } from '../utils/renderWithBridge';

import { act, cleanup, fireEvent, waitFor } from '@testing-library/react';

const MRZ_FIXTURE = {
  passportNumber: 'EU1234567',
  dateOfBirth: '900115',
  dateOfExpiry: '300115',
};

// The eu-id viewfinder validates documentNumber/dateOfBirth/dateOfExpiry on the scan
// result, so the scanMRZ fixture must carry documentNumber (not passportNumber).
const EUID_MRZ_SCAN = {
  documentNumber: 'EU1234567',
  dateOfBirth: '900115',
  dateOfExpiry: '300115',
};

// Valid-shape chip payload so the fail-closed normalizeNfcPassport (strict
// base64) accepts it and the flow reaches the success route.
const EUID_CHIP_FIXTURE = {
  mrz: 'IDUTOEU1234567<<<<<<<<<<<<<<<9001156M3001151UTO<<<<<<<<<<<8ANNA<<MARIA<<<<<<<<<<<<<<<<<<',
  documentSigningCertificate: '-----BEGIN CERTIFICATE-----\nMIICdummy\n-----END CERTIFICATE-----',
  eContent: 'AQIDBA==',
  encapContent: 'AQIDBA==',
  encryptedDigest: 'AQIDBA==',
  dataGroupHashes: { '1': 'aabb', '2': 'ccdd' },
};

describe('EU-ID and Aadhaar onboarding flows', () => {
  afterEach(cleanup);

  it('EU-ID NFC failure routes to the error screen with the support reference', async () => {
    const result = renderWithBridge({
      initialEntries: [{ pathname: '/capture/eu-id/nfc-instructions', state: { mrz: MRZ_FIXTURE } }],
      config: { mode: 'self-app', referenceId: 'ref-euid-nfc' },
      setupHandlers: mock => {
        mock.handleWithError('nfc', 'scanPassport', { code: 'NFC_READ_FAILED', message: 'chip read failed' });
      },
    });

    fireEvent.click(await waitFor(() => result.getByText('Continue')));

    await waitFor(() => expect(currentPath(result)).toBe('/capture/eu-id/nfc-error'));
    await waitFor(() => expect(result.getByText('Reference: ref-euid-nfc')).toBeTruthy());
  });

  it('EU-ID viewfinder surfaces native scan progress, then advances on MRZ result', async () => {
    let resolveScan!: (value: typeof EUID_MRZ_SCAN) => void;
    const result = renderWithBridge({
      initialEntries: ['/capture/eu-id/code-scan-viewfinder'],
      setupHandlers: mock => {
        mock.handle('camera', 'scanMRZ', () => new Promise<typeof EUID_MRZ_SCAN>(resolve => (resolveScan = resolve)));
      },
    });

    expect(result.getByRole('status').textContent).toContain('Opening the document scanner');

    act(() => result.mock.pushEvent('camera', 'scanProgress', { state: 'mrz_detected', message: 'Got the MRZ!' }));
    await waitFor(() => expect(result.getByRole('status').textContent).toContain('Got the MRZ!'));

    act(() => resolveScan(EUID_MRZ_SCAN));
    await waitFor(() => expect(currentPath(result)).toBe('/capture/eu-id/nfc-instructions'));
  });

  it('EU-ID viewfinder still navigates when the route re-renders mid native scan', async () => {
    let resolveScan!: (value: typeof EUID_MRZ_SCAN) => void;
    const result = renderWithBridge({
      initialEntries: ['/capture/eu-id/code-scan-viewfinder'],
      setupHandlers: mock => {
        mock.handle('camera', 'scanMRZ', () => new Promise<typeof EUID_MRZ_SCAN>(resolve => (resolveScan = resolve)));
      },
    });

    await waitFor(() => expect(result.getByRole('status')).toBeTruthy());
    act(() => result.forceRerender());

    act(() => resolveScan(EUID_MRZ_SCAN));
    await waitFor(() => expect(currentPath(result)).toBe('/capture/eu-id/nfc-instructions'));
  });

  it('EU-ID runs MRZ under StrictMode then NFC via Continue to success', async () => {
    // StrictMode double-invokes the viewfinder's auto-scan effect (setup→cleanup→setup).
    // The start-once guard means only the first setup starts the native scan; the
    // interleaved cleanup must not cancel that one in-flight scan (a closure `cancelled`
    // boolean did, dropping the MRZ so the flow hung on the viewfinder forever). A
    // reset-on-setup `cancelledRef` survives the benign cleanup. The eu-id NFC step is
    // button-driven (Continue), so it advances once tapped.
    let resolveScan!: (value: typeof EUID_MRZ_SCAN) => void;
    const result = renderWithBridge({
      initialEntries: ['/capture/eu-id/code-scan-viewfinder'],
      strictMode: true,
      setupHandlers: mock => {
        mock.handle('camera', 'scanMRZ', () => new Promise<typeof EUID_MRZ_SCAN>(resolve => (resolveScan = resolve)));
        mock.handleWith('nfc', 'scanPassport', EUID_CHIP_FIXTURE);
      },
    });

    await waitFor(() => expect(resolveScan).toBeTypeOf('function'));
    act(() => resolveScan(EUID_MRZ_SCAN));
    await waitFor(() => expect(currentPath(result)).toBe('/capture/eu-id/nfc-instructions'));

    fireEvent.click(await waitFor(() => result.getByText('Continue')));
    await waitFor(() => expect(currentPath(result)).toBe('/capture/eu-id/nfc-success'));
  });

  it('EU-ID incomplete MRZ result routes to the error screen under StrictMode', async () => {
    // Exercises the viewfinder catch branch (missing dateOfExpiry → "Incomplete MRZ
    // result") and its cancelledRef guard under StrictMode's benign cleanup.
    const result = renderWithBridge({
      initialEntries: ['/capture/eu-id/code-scan-viewfinder'],
      strictMode: true,
      setupHandlers: mock => {
        mock.handleWith('camera', 'scanMRZ', { documentNumber: 'EU1234567', dateOfBirth: '900115' });
      },
    });

    await waitFor(() => expect(currentPath(result)).toBe('/capture/eu-id/nfc-error'));
  });

  it('Aadhaar upload with no native handler routes to the upload-error screen with the footer', async () => {
    const result = renderWithBridge({
      initialEntries: ['/capture/aadhaar/instructions'],
      config: { mode: 'self-app', referenceId: 'ref-aadhaar' },
      // No camera/aadhaarUploadFromLibrary handler: the bridge replies NO_HANDLER,
      // which is the shipped placeholder failure mode until a native handler exists.
    });

    fireEvent.click(await waitFor(() => result.getByText('Upload')));

    await waitFor(() => expect(currentPath(result)).toBe('/capture/aadhaar/upload-error'));
    await waitFor(() => expect(result.getByText('Reference: ref-aadhaar')).toBeTruthy());
  });
});
