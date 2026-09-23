// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// @vitest-environment jsdom

import type React from 'react';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';

import { useVerificationRequest, VerificationRequestProvider } from '../../src/providers/VerificationRequestProvider';

import { cleanup, fireEvent, render } from '@testing-library/react';

const Probe: React.FC = () => {
  const navigate = useNavigate();
  const { request } = useVerificationRequest();
  return (
    <div>
      <div data-testid="disclosures" data-value={(request.disclosures ?? []).join(',')} />
      <button type="button" data-testid="onboard" onClick={() => navigate('/capture/kyc')}>
        onboard
      </button>
    </div>
  );
};

function renderAt(entry: string) {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <VerificationRequestProvider>
        <Probe />
      </VerificationRequestProvider>
    </MemoryRouter>,
  );
}

describe('VerificationRequestProvider sticky capture', () => {
  afterEach(() => {
    cleanup();
  });

  it('retains the request after in-session navigation drops the query', () => {
    const result = renderAt('/tunnel/tour/1?disclosures=ofac,nationality');

    expect(result.getByTestId('disclosures').getAttribute('data-value')).toBe('ofac,nationality');

    // Onboarding navigation wipes the launch query (no `search`).
    fireEvent.click(result.getByTestId('onboard'));

    // The captured request survives so the post-registration resume still has it.
    expect(result.getByTestId('disclosures').getAttribute('data-value')).toBe('ofac,nationality');
  });

  it('exposes an empty request when none was ever supplied', () => {
    const result = renderAt('/');
    expect(result.getByTestId('disclosures').getAttribute('data-value')).toBe('');
  });
});
