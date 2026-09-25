// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KeychainHandler } from '../handlers/KeychainHandler';
import type {
  KeychainModule,
  SecureStorageStore,
} from '../handlers/KeychainHandler';

function createMockKeychain(): KeychainModule {
  return {
    getGenericPassword: vi.fn(),
    setGenericPassword: vi.fn(),
    resetGenericPassword: vi.fn(),
  };
}

function createMockStore(): SecureStorageStore {
  return {
    get: vi.fn(),
    set: vi.fn(),
    remove: vi.fn(),
  };
}

describe('KeychainHandler', () => {
  let handler: KeychainHandler;
  let mockKeychain: KeychainModule;

  beforeEach(() => {
    mockKeychain = createMockKeychain();
    handler = new KeychainHandler(mockKeychain);
    vi.clearAllMocks();
  });

  it('has domain "secureStorage"', () => {
    expect(handler.domain).toBe('secureStorage');
  });

  describe('set + get roundtrip', () => {
    it('stores a value and retrieves it', async () => {
      (
        mockKeychain.setGenericPassword as ReturnType<typeof vi.fn>
      ).mockResolvedValue(true);
      (
        mockKeychain.getGenericPassword as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        username: 'auth_token',
        password: 'abc123',
      });

      const setResult = await handler.handle('set', {
        key: 'auth_token',
        value: 'abc123',
      });
      expect(setResult).toBeNull();
      expect(mockKeychain.setGenericPassword).toHaveBeenCalledWith(
        'auth_token',
        'abc123',
        { service: 'self_sdk_auth_token' },
      );

      const getResult = await handler.handle('get', { key: 'auth_token' });
      expect(getResult).toBe('abc123');
      expect(mockKeychain.getGenericPassword).toHaveBeenCalledWith({
        service: 'self_sdk_auth_token',
      });
    });
  });

  describe('get', () => {
    it('returns null for nonexistent key', async () => {
      (
        mockKeychain.getGenericPassword as ReturnType<typeof vi.fn>
      ).mockResolvedValue(false);

      const result = await handler.handle('get', { key: 'nonexistent' });
      expect(result).toBeNull();
    });
  });

  describe('remove', () => {
    it('removes a key and returns null', async () => {
      (
        mockKeychain.resetGenericPassword as ReturnType<typeof vi.fn>
      ).mockResolvedValue(true);

      const result = await handler.handle('remove', { key: 'auth_token' });
      expect(result).toBeNull();
      expect(mockKeychain.resetGenericPassword).toHaveBeenCalledWith({
        service: 'self_sdk_auth_token',
      });
    });
  });

  describe('validation', () => {
    it('throws MISSING_KEY when key param absent on get', async () => {
      try {
        await handler.handle('get', {});
        expect.unreachable('Should have thrown');
      } catch (err: unknown) {
        expect((err as { code: string }).code).toBe('MISSING_KEY');
        expect((err as Error).message).toContain('Key parameter required');
      }
    });

    it('throws MISSING_KEY when key param absent on set', async () => {
      try {
        await handler.handle('set', { value: 'v' });
        expect.unreachable('Should have thrown');
      } catch (err: unknown) {
        expect((err as { code: string }).code).toBe('MISSING_KEY');
      }
    });

    it('throws MISSING_VALUE when value param absent on set', async () => {
      try {
        await handler.handle('set', { key: 'k' });
        expect.unreachable('Should have thrown');
      } catch (err: unknown) {
        expect((err as { code: string }).code).toBe('MISSING_VALUE');
        expect((err as Error).message).toContain('Value parameter required');
      }
    });
  });

  describe('unknown method', () => {
    it('throws METHOD_NOT_FOUND', async () => {
      await expect(handler.handle('clear', {})).rejects.toThrow(
        'Unknown secureStorage method: clear',
      );
    });
  });

  describe('injected SecureStorageStore', () => {
    let store: SecureStorageStore;
    let storeHandler: KeychainHandler;

    beforeEach(() => {
      store = createMockStore();
      storeHandler = new KeychainHandler(mockKeychain, store);
    });

    it('is available when a store is provided', () => {
      expect(storeHandler.isAvailable()).toBe(true);
    });

    it('delegates get to the store and forwards requireBiometric', async () => {
      (store.get as ReturnType<typeof vi.fn>).mockResolvedValue('stored');

      const result = await storeHandler.handle('get', {
        key: 'k',
        requireBiometric: true,
      });

      expect(result).toBe('stored');
      expect(store.get).toHaveBeenCalledWith('k', { requireBiometric: true });
      expect(mockKeychain.getGenericPassword).not.toHaveBeenCalled();
    });

    it('delegates set to the store and returns null', async () => {
      (store.set as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

      const result = await storeHandler.handle('set', { key: 'k', value: 'v' });

      expect(result).toBeNull();
      expect(store.set).toHaveBeenCalledWith('k', 'v');
      expect(mockKeychain.setGenericPassword).not.toHaveBeenCalled();
    });

    it('delegates remove to the store and returns null', async () => {
      (store.remove as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

      const result = await storeHandler.handle('remove', { key: 'k' });

      expect(result).toBeNull();
      expect(store.remove).toHaveBeenCalledWith('k');
      expect(mockKeychain.resetGenericPassword).not.toHaveBeenCalled();
    });

    it('still validates key/value params', async () => {
      await expect(storeHandler.handle('get', {})).rejects.toThrow(
        'Key parameter required',
      );
      await expect(storeHandler.handle('set', { key: 'k' })).rejects.toThrow(
        'Value parameter required',
      );
    });
  });
});
