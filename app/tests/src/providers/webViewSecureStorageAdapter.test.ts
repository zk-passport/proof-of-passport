// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// The adapter's default deps pull in the app's legacy keychain primitives which
// drag heavy native/expo modules into the jest graph. We inject mock deps into
// the factory instead (the translation logic is the unit under test), so these
// module mocks only need to keep the top-level imports resolvable.
import type { WebViewSecureStorageDeps } from '@/providers/webViewSecureStorageAdapter';
import { createWebViewSecureStorageAdapter } from '@/providers/webViewSecureStorageAdapter';

jest.mock('react-native-keychain', () => ({ __esModule: true, default: {} }));
jest.mock('@/integrations/keychain', () => ({
  __esModule: true,
  createKeychainOptions: jest.fn(),
}));
jest.mock('@/providers/authProvider', () => ({
  __esModule: true,
  hasSecretStored: jest.fn(),
  getPrivateKeyFromMnemonic: jest.fn(),
  getStoredMnemonicPhrase: jest.fn(),
  restoreMnemonicPhrase: jest.fn(),
}));
jest.mock('@/providers/passportDataProvider', () => ({
  __esModule: true,
  loadDocumentCatalogDirectlyFromKeychain: jest.fn(),
  saveDocumentCatalogDirectlyToKeychain: jest.fn(),
  loadDocumentByIdDirectlyFromKeychain: jest.fn(),
  deleteDocumentDirectlyFromKeychain: jest.fn(),
  selfClientDocumentsAdapter: { saveDocument: jest.fn() },
}));

function makeDeps(overrides: Partial<WebViewSecureStorageDeps> = {}) {
  const deps: jest.Mocked<WebViewSecureStorageDeps> = {
    hasSecretStored: jest.fn().mockResolvedValue(true),
    readMnemonicPhrase: jest.fn().mockResolvedValue(null),
    writeNewMnemonic: jest.fn().mockResolvedValue(undefined),
    derivePrivateKey: jest.fn().mockReturnValue('0xderived'),
    loadDocumentCatalog: jest.fn().mockResolvedValue({ documents: [] }),
    saveDocumentCatalog: jest.fn().mockResolvedValue(undefined),
    loadDocumentById: jest.fn().mockResolvedValue(null),
    saveDocument: jest.fn().mockResolvedValue(undefined),
    deleteDocument: jest.fn().mockResolvedValue(undefined),
    passthroughGet: jest.fn().mockResolvedValue(null),
    passthroughSet: jest.fn().mockResolvedValue(undefined),
    passthroughRemove: jest.fn().mockResolvedValue(undefined),
    ...overrides,
  } as jest.Mocked<WebViewSecureStorageDeps>;
  return deps;
}

describe('createWebViewSecureStorageAdapter', () => {
  describe('get', () => {
    it('returns the legacy mnemonic phrase for self_mnemonic', async () => {
      const deps = makeDeps({
        readMnemonicPhrase: jest.fn().mockResolvedValue('twelve word phrase'),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(store.get('self_mnemonic')).resolves.toBe(
        'twelve word phrase',
      );
      expect(deps.readMnemonicPhrase).toHaveBeenCalledTimes(1);
    });

    it('derives the private key and forwards requireBiometric for self_private_key', async () => {
      const deps = makeDeps({
        readMnemonicPhrase: jest.fn().mockResolvedValue('the phrase'),
        derivePrivateKey: jest.fn().mockReturnValue('0xabc123'),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(
        store.get('self_private_key', { requireBiometric: true }),
      ).resolves.toBe('0xabc123');
      expect(deps.readMnemonicPhrase).toHaveBeenCalledWith({
        requireBiometric: true,
      });
      expect(deps.derivePrivateKey).toHaveBeenCalledWith('the phrase');
    });

    it('returns null for self_private_key when no legacy mnemonic exists', async () => {
      const deps = makeDeps({
        readMnemonicPhrase: jest.fn().mockResolvedValue(null),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(store.get('self_private_key')).resolves.toBeNull();
      expect(deps.derivePrivateKey).not.toHaveBeenCalled();
    });

    it('returns the stringified catalog for self_document_catalog', async () => {
      const catalog = { documents: [{ id: 'abc' }], selectedDocumentId: 'abc' };
      const deps = makeDeps({
        loadDocumentCatalog: jest.fn().mockResolvedValue(catalog),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(store.get('self_document_catalog')).resolves.toBe(
        JSON.stringify(catalog),
      );
    });

    it('returns null for an empty catalog', async () => {
      const deps = makeDeps({
        loadDocumentCatalog: jest.fn().mockResolvedValue({ documents: [] }),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(store.get('self_document_catalog')).resolves.toBeNull();
    });

    it('strips the self_doc_ prefix and returns the stringified document', async () => {
      const doc = { mrz: 'P<...' };
      const deps = makeDeps({
        loadDocumentById: jest.fn().mockResolvedValue(doc),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(store.get('self_doc_hash123')).resolves.toBe(
        JSON.stringify(doc),
      );
      expect(deps.loadDocumentById).toHaveBeenCalledWith('hash123');
    });

    it('returns null when the document is missing', async () => {
      const deps = makeDeps({
        loadDocumentById: jest.fn().mockResolvedValue(null),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(store.get('self_doc_missing')).resolves.toBeNull();
    });

    it('passes through unknown keys', async () => {
      const deps = makeDeps({
        passthroughGet: jest.fn().mockResolvedValue('passthrough-value'),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await expect(store.get('some_other_key')).resolves.toBe(
        'passthrough-value',
      );
      expect(deps.passthroughGet).toHaveBeenCalledWith('some_other_key');
    });
  });

  describe('set', () => {
    it('is a no-op for self_mnemonic when an identity already exists', async () => {
      const deps = makeDeps({
        hasSecretStored: jest.fn().mockResolvedValue(true),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await store.set('self_mnemonic', 'new phrase');

      expect(deps.writeNewMnemonic).not.toHaveBeenCalled();
    });

    it('writes a new mnemonic for self_mnemonic when no identity exists', async () => {
      const deps = makeDeps({
        hasSecretStored: jest.fn().mockResolvedValue(false),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await store.set('self_mnemonic', 'brand new phrase');

      expect(deps.writeNewMnemonic).toHaveBeenCalledWith('brand new phrase');
    });

    it('is always a no-op for self_private_key', async () => {
      const deps = makeDeps({
        hasSecretStored: jest.fn().mockResolvedValue(false),
      });
      const store = createWebViewSecureStorageAdapter(deps);

      await store.set('self_private_key', '0xshould-not-persist');

      expect(deps.writeNewMnemonic).not.toHaveBeenCalled();
      expect(deps.passthroughSet).not.toHaveBeenCalled();
    });

    it('parses and saves the catalog for self_document_catalog', async () => {
      const catalog = { documents: [{ id: 'x' }] };
      const deps = makeDeps();
      const store = createWebViewSecureStorageAdapter(deps);

      await store.set('self_document_catalog', JSON.stringify(catalog));

      expect(deps.saveDocumentCatalog).toHaveBeenCalledWith(catalog);
    });

    it('strips the prefix and saves the document for self_doc_{id}', async () => {
      const doc = { mrz: 'DATA' };
      const deps = makeDeps();
      const store = createWebViewSecureStorageAdapter(deps);

      await store.set('self_doc_hash789', JSON.stringify(doc));

      expect(deps.saveDocument).toHaveBeenCalledWith('hash789', doc);
    });

    it('passes through unknown keys', async () => {
      const deps = makeDeps();
      const store = createWebViewSecureStorageAdapter(deps);

      await store.set('other', 'val');

      expect(deps.passthroughSet).toHaveBeenCalledWith('other', 'val');
    });
  });

  describe('remove', () => {
    it('strips the prefix and deletes the document for self_doc_{id}', async () => {
      const deps = makeDeps();
      const store = createWebViewSecureStorageAdapter(deps);

      await store.remove('self_doc_hashDEL');

      expect(deps.deleteDocument).toHaveBeenCalledWith('hashDEL');
    });

    it('never deletes the legacy identity keys', async () => {
      const deps = makeDeps();
      const store = createWebViewSecureStorageAdapter(deps);

      await store.remove('self_mnemonic');
      await store.remove('self_private_key');
      await store.remove('self_document_catalog');

      expect(deps.deleteDocument).not.toHaveBeenCalled();
      expect(deps.saveDocumentCatalog).not.toHaveBeenCalled();
      expect(deps.passthroughRemove).not.toHaveBeenCalled();
    });

    it('passes through unknown keys', async () => {
      const deps = makeDeps();
      const store = createWebViewSecureStorageAdapter(deps);

      await store.remove('other');

      expect(deps.passthroughRemove).toHaveBeenCalledWith('other');
    });
  });
});
