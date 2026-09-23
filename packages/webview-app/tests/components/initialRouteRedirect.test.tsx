// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// @vitest-environment jsdom

import type React from 'react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InitialRouteRedirect } from '../../src/components/InitialRouteRedirect';

import { cleanup, render, waitFor } from '@testing-library/react';

const { resolveEmbedEntryMock } = vi.hoisted(() => ({ resolveEmbedEntryMock: vi.fn() }));

vi.mock('../../src/utils/resolveEmbedEntry', () => ({
  resolveEmbedEntry: resolveEmbedEntryMock,
}));

vi.mock('../../src/providers/SelfClientProvider', () => ({
  useSelfClient: () => ({ client: {} }),
}));

const Probe: React.FC = () => {
  const location = useLocation();
  return <div data-testid="loc" data-path={`${location.pathname}${location.search}`} />;
};

function renderAt(entry: string) {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <Routes>
        <Route path="/" element={<Probe />} />
        <Route path="/tour/1" element={<Probe />} />
        <Route path="/disclose/request" element={<Probe />} />
        <Route path="*" element={<InitialRouteRedirect />} />
      </Routes>
    </MemoryRouter>,
  );
}

async function settledPath(result: ReturnType<typeof render>): Promise<string> {
  const probe = await waitFor(() => result.getByTestId('loc'));
  return probe.getAttribute('data-path') ?? '';
}

describe('InitialRouteRedirect', () => {
  beforeEach(() => {
    resolveEmbedEntryMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('sends a registered user with a verification request to the disclose request, preserving the query', async () => {
    resolveEmbedEntryMock.mockResolvedValue('/disclose/request');
    const result = renderAt('/tunnel/tour/1?disclosures=ofac');

    expect(await settledPath(result)).toBe('/disclose/request?disclosures=ofac');
    expect(resolveEmbedEntryMock).toHaveBeenCalledWith({}, '/tour/1');
  });

  it('routes an unregistered user with a verification request into onboarding', async () => {
    resolveEmbedEntryMock.mockResolvedValue('/tour/1');
    const result = renderAt('/tunnel/tour/1?disclosures=ofac');

    expect(await settledPath(result)).toBe('/tour/1?disclosures=ofac');
  });

  it('keys off proofItems as well as disclosures', async () => {
    resolveEmbedEntryMock.mockResolvedValue('/disclose/request');
    const result = renderAt('/anything?proofItems=name');

    expect(await settledPath(result)).toBe('/disclose/request?proofItems=name');
    expect(resolveEmbedEntryMock).toHaveBeenCalled();
  });

  it('redirects to home and never checks document state without a request param', async () => {
    const result = renderAt('/unmatched-path');

    expect(await settledPath(result)).toBe('/');
    expect(resolveEmbedEntryMock).not.toHaveBeenCalled();
  });
});
