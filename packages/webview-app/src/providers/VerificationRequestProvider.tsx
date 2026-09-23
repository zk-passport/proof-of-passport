// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type React from 'react';
import { createContext, useContext, useMemo, useRef } from 'react';
import { useLocation } from 'react-router-dom';

import type { ParsedVerificationRequestContext } from '../utils/verificationRequest';
import { hasDiscloseRequestContext, parseVerificationRequestContext } from '../utils/verificationRequest';

export type VerificationRequestContext = ParsedVerificationRequestContext;

const Ctx = createContext<VerificationRequestContext | null>(null);

export const VerificationRequestProvider: React.FC<{
  children: React.ReactNode;
}> = ({ children }) => {
  const { search } = useLocation();

  // Sticky capture: BrowserRouter wipes the launch query during onboarding
  // navigation (prod capture routes navigate without `search`), so the request
  // would be lost before the user reaches `/disclose/request`. Hold the last
  // parse that actually carried a request so in-session navigation can't drop
  // it. The host re-supplies the URL on every WebView launch, so this only
  // needs to survive in-session, not across launches.
  const stickyRef = useRef<VerificationRequestContext | null>(null);

  const value = useMemo(() => {
    const parsed = parseVerificationRequestContext(search || window.location.search);
    if (hasDiscloseRequestContext(parsed)) {
      stickyRef.current = parsed;
      return parsed;
    }
    return stickyRef.current ?? parsed;
  }, [search]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
};

export function useVerificationRequest(): VerificationRequestContext {
  const ctx = useContext(Ctx);
  if (!ctx) {
    throw new Error('useVerificationRequest must be used within a VerificationRequestProvider');
  }
  return ctx;
}
