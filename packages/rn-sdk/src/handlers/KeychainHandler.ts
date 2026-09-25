// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import type { BridgeDomain } from '../bridge/types';
import type { BridgeHandler } from '../bridge/types';
import { BridgeHandlerError } from '../bridge/types';

export interface KeychainModule {
  getGenericPassword(opts: {
    service: string;
  }): Promise<false | { username: string; password: string }>;
  setGenericPassword(
    username: string,
    password: string,
    opts: { service: string },
  ): Promise<boolean>;
  resetGenericPassword(opts: { service: string }): Promise<boolean>;
}

export interface SecureStorageStore {
  get(
    key: string,
    opts?: { requireBiometric?: boolean },
  ): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

function loadKeychain(): KeychainModule | undefined {
  try {
    return require('react-native-keychain') as KeychainModule;
  } catch {
    return undefined;
  }
}

const SERVICE_PREFIX = 'self_sdk_';

export class KeychainHandler implements BridgeHandler {
  readonly domain: BridgeDomain = 'secureStorage';
  private readonly keychain: KeychainModule | undefined;
  private readonly store: SecureStorageStore | undefined;

  constructor(keychain?: KeychainModule, store?: SecureStorageStore) {
    this.store = store;
    this.keychain = store ? undefined : (keychain ?? loadKeychain());
  }

  isAvailable(): boolean {
    return this.store !== undefined || this.keychain !== undefined;
  }

  async handle(
    method: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    if (!this.store && !this.keychain) {
      throw new BridgeHandlerError(
        'NOT_AVAILABLE',
        'react-native-keychain is not installed',
      );
    }

    switch (method) {
      case 'get': {
        const key = params.key as string | undefined;
        if (!key)
          throw new BridgeHandlerError('MISSING_KEY', 'Key parameter required');
        if (this.store) {
          return await this.store.get(key, {
            requireBiometric: params.requireBiometric as boolean | undefined,
          });
        }
        const credentials = await this.keychain!.getGenericPassword({
          service: `${SERVICE_PREFIX}${key}`,
        });
        return credentials ? credentials.password : null;
      }
      case 'set': {
        const key = params.key as string | undefined;
        const value = params.value as string | undefined;
        if (!key)
          throw new BridgeHandlerError('MISSING_KEY', 'Key parameter required');
        if (value === undefined || value === null) {
          throw new BridgeHandlerError(
            'MISSING_VALUE',
            'Value parameter required',
          );
        }
        if (this.store) {
          await this.store.set(key, value);
          return null;
        }
        await this.keychain!.setGenericPassword(key, value, {
          service: `${SERVICE_PREFIX}${key}`,
        });
        return null;
      }
      case 'remove': {
        const key = params.key as string | undefined;
        if (!key)
          throw new BridgeHandlerError('MISSING_KEY', 'Key parameter required');
        if (this.store) {
          await this.store.remove(key);
          return null;
        }
        await this.keychain!.resetGenericPassword({
          service: `${SERVICE_PREFIX}${key}`,
        });
        return null;
      }
      default:
        throw new BridgeHandlerError(
          'METHOD_NOT_FOUND',
          `Unknown secureStorage method: ${method}`,
        );
    }
  }
}
