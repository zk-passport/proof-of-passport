// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import Keychain from 'react-native-keychain';

import type {
  DocumentCatalog,
  PassportData,
} from '@selfxyz/common/utils/types';
import type { SecureStorageStore } from '@selfxyz/rn-sdk';

import {
  getPrivateKeyFromMnemonic,
  getStoredMnemonicPhrase,
  hasSecretStored,
  restoreMnemonicPhrase,
} from '@/providers/authProvider';
import {
  deleteDocumentDirectlyFromKeychain,
  loadDocumentByIdDirectlyFromKeychain,
  loadDocumentCatalogDirectlyFromKeychain,
  saveDocumentCatalogDirectlyToKeychain,
  selfClientDocumentsAdapter,
} from '@/providers/passportDataProvider';

// WebView secureStorage production keys.
export const MNEMONIC_KEY = 'self_mnemonic';
export const PRIVATE_KEY_KEY = 'self_private_key';
export const DOCUMENT_CATALOG_KEY = 'self_document_catalog';
export const DOC_KEY_PREFIX = 'self_doc_';

// Mirrors the SDK KeychainHandler fallback service prefix so non-identity keys
// behave exactly like the default react-native-keychain store.
const PASSTHROUGH_SERVICE_PREFIX = 'self_sdk_';

/**
 * Ports the translator needs. Kept as an injectable dependency bag so the pure
 * key-routing / write-guard logic is standalone and reusable (a future KMP-side
 * provider can supply its own implementations). Defaults wire the app's legacy
 * keychain primitives.
 */
export interface WebViewSecureStorageDeps {
  hasSecretStored(): Promise<boolean>;
  readMnemonicPhrase(opts?: {
    requireBiometric?: boolean;
  }): Promise<string | null>;
  writeNewMnemonic(phrase: string): Promise<void>;
  derivePrivateKey(phrase: string): string;
  loadDocumentCatalog(): Promise<DocumentCatalog>;
  saveDocumentCatalog(catalog: DocumentCatalog): Promise<void>;
  loadDocumentById(id: string): Promise<PassportData | null>;
  saveDocument(id: string, data: PassportData): Promise<void>;
  deleteDocument(id: string): Promise<void>;
  passthroughGet(key: string): Promise<string | null>;
  passthroughSet(key: string, value: string): Promise<void>;
  passthroughRemove(key: string): Promise<void>;
}

async function passthroughGet(key: string): Promise<string | null> {
  const creds = await Keychain.getGenericPassword({
    service: `${PASSTHROUGH_SERVICE_PREFIX}${key}`,
  });
  return creds ? creds.password : null;
}

async function passthroughSet(key: string, value: string): Promise<void> {
  await Keychain.setGenericPassword(key, value, {
    service: `${PASSTHROUGH_SERVICE_PREFIX}${key}`,
  });
}

async function passthroughRemove(key: string): Promise<void> {
  await Keychain.resetGenericPassword({
    service: `${PASSTHROUGH_SERVICE_PREFIX}${key}`,
  });
}

function createDefaultDeps(): WebViewSecureStorageDeps {
  return {
    hasSecretStored,
    readMnemonicPhrase: getStoredMnemonicPhrase,
    writeNewMnemonic: restoreMnemonicPhrase,
    derivePrivateKey: getPrivateKeyFromMnemonic,
    loadDocumentCatalog: loadDocumentCatalogDirectlyFromKeychain,
    saveDocumentCatalog: saveDocumentCatalogDirectlyToKeychain,
    loadDocumentById: loadDocumentByIdDirectlyFromKeychain,
    saveDocument: (id, data) =>
      selfClientDocumentsAdapter.saveDocument(id, data as never),
    deleteDocument: deleteDocumentDirectlyFromKeychain,
    passthroughGet,
    passthroughSet,
    passthroughRemove,
  };
}

/**
 * Host-side translating secureStorage store: lets the app-hosted WebView read and
 * write the user's EXISTING legacy keychain (identity + documents) instead of a
 * separate `self_sdk_*` store. No migration/copy; the existing identity is never
 * clobbered.
 */
export function createWebViewSecureStorageAdapter(
  deps: WebViewSecureStorageDeps = createDefaultDeps(),
): SecureStorageStore {
  return {
    async get(key, opts) {
      if (key === MNEMONIC_KEY) {
        return deps.readMnemonicPhrase(opts);
      }
      if (key === PRIVATE_KEY_KEY) {
        const phrase = await deps.readMnemonicPhrase(opts);
        if (!phrase) {
          return null;
        }
        try {
          return deps.derivePrivateKey(phrase);
        } catch {
          return null;
        }
      }
      if (key === DOCUMENT_CATALOG_KEY) {
        const catalog = await deps.loadDocumentCatalog();
        if (!catalog?.documents?.length) {
          return null;
        }
        return JSON.stringify(catalog);
      }
      if (key.startsWith(DOC_KEY_PREFIX)) {
        const id = key.slice(DOC_KEY_PREFIX.length);
        const doc = await deps.loadDocumentById(id);
        return doc ? JSON.stringify(doc) : null;
      }
      return deps.passthroughGet(key);
    },

    async set(key, value) {
      if (key === MNEMONIC_KEY) {
        // Identity write-guard: never overwrite an existing identity. Only a
        // genuine new user (no legacy secret) may write a fresh mnemonic.
        if (await deps.hasSecretStored()) {
          return;
        }
        await deps.writeNewMnemonic(value);
        return;
      }
      if (key === PRIVATE_KEY_KEY) {
        // Always a no-op: the private key is derived from the mnemonic and is
        // never persisted in legacy storage.
        return;
      }
      if (key === DOCUMENT_CATALOG_KEY) {
        await deps.saveDocumentCatalog(JSON.parse(value) as DocumentCatalog);
        return;
      }
      if (key.startsWith(DOC_KEY_PREFIX)) {
        const id = key.slice(DOC_KEY_PREFIX.length);
        await deps.saveDocument(id, JSON.parse(value) as PassportData);
        return;
      }
      await deps.passthroughSet(key, value);
    },

    async remove(key) {
      if (key === MNEMONIC_KEY || key === PRIVATE_KEY_KEY) {
        // Never delete the legacy identity from the WebView.
        return;
      }
      if (key === DOCUMENT_CATALOG_KEY) {
        // No dedicated catalog-delete primitive; deleting it would orphan every
        // stored document, so treat as a no-op (non-destructive default).
        return;
      }
      if (key.startsWith(DOC_KEY_PREFIX)) {
        const id = key.slice(DOC_KEY_PREFIX.length);
        await deps.deleteDocument(id);
        return;
      }
      await deps.passthroughRemove(key);
    },
  };
}
