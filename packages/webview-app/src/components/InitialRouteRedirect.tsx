// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { useSelfClient } from '../providers/SelfClientProvider';
import { resolveEmbedEntry } from '../utils/resolveEmbedEntry';
import { hasVerificationRequestParam } from '../utils/verificationRequest';

/**
 * Catch-all entry. The SDK launches the WebView at `…/tunnel/tour/1?disclosures=…`,
 * which matches no route and lands here. On a verification-request param
 * (`disclosures` | `proofItems`) the destination is doc-aware: a registered
 * document goes straight to the proof request, an unregistered/unknown one
 * starts onboarding at `/tour/1` instead of force-jumping to a proof the user
 * cannot satisfy. Entries without a request param keep the old behavior (`/`).
 */
export const InitialRouteRedirect: React.FC = () => {
  const location = useLocation();
  const { client } = useSelfClient();
  const hasRequest = hasVerificationRequestParam(location.search);

  const [target, setTarget] = useState<string | null>(null);

  useEffect(() => {
    if (!hasRequest) return undefined;
    let cancelled = false;
    void resolveEmbedEntry(client, '/tour/1').then(route => {
      if (!cancelled) setTarget(route);
    });
    return () => {
      cancelled = true;
    };
  }, [hasRequest, client]);

  if (!hasRequest) {
    return <Navigate to="/" replace />;
  }

  // Resolving document state — render nothing (matches BootDecision's boot
  // convention). The IndexedDB read is fast and one-shot.
  if (target === null) {
    return null;
  }

  // Preserve the launch query through the redirect. Sticky capture in
  // VerificationRequestProvider covers later in-session navigation that drops it.
  return <Navigate to={{ pathname: target, search: location.search }} replace />;
};
