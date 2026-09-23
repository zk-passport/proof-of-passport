// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { SelfClient } from '@selfxyz/mobile-sdk-alpha/browser';

import { DISCLOSE_ROUTE, resolveEmbedEntry } from '../../src/utils/resolveEmbedEntry';

const { loadSelectedDocumentMock } = vi.hoisted(() => ({ loadSelectedDocumentMock: vi.fn() }));

vi.mock('@selfxyz/mobile-sdk-alpha/browser', () => ({
  loadSelectedDocument: loadSelectedDocumentMock,
}));

const client = {} as SelfClient;

describe('resolveEmbedEntry', () => {
  beforeEach(() => {
    loadSelectedDocumentMock.mockReset();
  });

  it('routes a registered document straight to the disclose request', async () => {
    loadSelectedDocumentMock.mockResolvedValue({ metadata: { isRegistered: true } });
    expect(await resolveEmbedEntry(client, '/tour/1')).toBe(DISCLOSE_ROUTE);
  });

  it('routes an unregistered document to the onboarding fallback', async () => {
    loadSelectedDocumentMock.mockResolvedValue({ metadata: { isRegistered: false } });
    expect(await resolveEmbedEntry(client, '/tour/1')).toBe('/tour/1');
  });

  it('routes to the fallback when there is no selected document', async () => {
    loadSelectedDocumentMock.mockResolvedValue(null);
    expect(await resolveEmbedEntry(client, '/capture/kyc')).toBe('/capture/kyc');
  });

  it('fails toward onboarding when document state is unavailable', async () => {
    loadSelectedDocumentMock.mockRejectedValue(new Error('catalog read failed'));
    expect(await resolveEmbedEntry(client, '/tour/1')).toBe('/tour/1');
  });

  it('preserves whatever fallback the caller supplies', async () => {
    loadSelectedDocumentMock.mockResolvedValue({ metadata: { isRegistered: false } });
    expect(await resolveEmbedEntry(client, '/capture/kyc?mock=demo')).toBe('/capture/kyc?mock=demo');
  });
});
