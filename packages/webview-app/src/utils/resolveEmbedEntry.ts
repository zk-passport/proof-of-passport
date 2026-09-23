// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type { SelfClient } from '@selfxyz/mobile-sdk-alpha/browser';
import { loadSelectedDocument } from '@selfxyz/mobile-sdk-alpha/browser';

export const DISCLOSE_ROUTE = '/disclose/request';

/**
 * Doc-aware embed entry decision shared by the catch-all redirect and the
 * end-of-tour handoff. Resolves to the disclose screen when the selected
 * document is already registered, otherwise to `unregisteredRoute` — the
 * caller's onboarding entry (`/tour/1` from a cold launch, `/capture/kyc`
 * from the end of the tour).
 *
 * Any failure to read document state falls through to onboarding: fail toward
 * scanning, never into a proof request the user has no document to satisfy.
 */
export async function resolveEmbedEntry(client: SelfClient, unregisteredRoute: string): Promise<string> {
  try {
    const selectedDoc = await loadSelectedDocument(client);
    if (selectedDoc?.metadata?.isRegistered === true) {
      return DISCLOSE_ROUTE;
    }
  } catch {
    // Document state unavailable — fall through to onboarding.
  }
  return unregisteredRoute;
}
