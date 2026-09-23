// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// The shared error screen's default copy blames the NFC chip, but an MRZ-stage
// failure happened at the camera step, before any chip contact — telling the
// user the chip failed sends them retrying the wrong thing.
const MRZ_STAGE_ERROR_COPY = {
  title: 'There was a problem scanning your document',
  body: "Let's try again or register a different way",
} as const;

export const nfcErrorCopyForStage = (stage?: 'mrz' | 'nfc'): typeof MRZ_STAGE_ERROR_COPY | undefined =>
  stage === 'mrz' ? MRZ_STAGE_ERROR_COPY : undefined;
