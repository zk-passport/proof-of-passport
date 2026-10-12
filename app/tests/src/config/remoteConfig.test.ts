// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

// Now import the module under test
// Import the mocked AsyncStorage for test controls
import AsyncStorage from '@react-native-async-storage/async-storage';

import {
  clearAllLocalOverrides,
  clearLocalOverride,
  getAllFeatureFlags,
  getFeatureFlag,
  getLocalOverrides,
  initRemoteConfig,
  readFeatureFlag,
  refreshRemoteConfig,
  setLocalOverride,
  subscribeToRemoteConfig,
} from '@/config/remoteConfig';

// Mock AsyncStorage with a default export
jest.mock('@react-native-async-storage/async-storage', () => ({
  __esModule: true,
  default: {
    getItem: jest.fn(),
    setItem: jest.fn(),
    removeItem: jest.fn(),
  },
}));

// Mock Firebase Remote Config with proper setup
const mockRemoteConfigInstance = {
  setDefaults: jest.fn(),
  setConfigSettings: jest.fn(),
  fetchAndActivate: jest.fn(),
  activate: jest.fn(),
  onConfigUpdated: jest.fn(() => jest.fn()),
  getValue: jest.fn(),
  getAll: jest.fn(),
};

jest.mock('@react-native-firebase/remote-config', () => ({
  __esModule: true,
  default: () => mockRemoteConfigInstance,
}));

// Get the mock instances
const mockAsyncStorage = AsyncStorage as jest.Mocked<typeof AsyncStorage>;
const mockRemoteConfig = mockRemoteConfigInstance as jest.Mocked<
  typeof mockRemoteConfigInstance
>;

describe('RemoteConfig', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockAsyncStorage.getItem.mockResolvedValue('{}');
    mockAsyncStorage.setItem.mockResolvedValue();
    mockAsyncStorage.removeItem.mockResolvedValue();
  });

  // Suppress console errors during testing
  beforeAll(() => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });

  describe('getFeatureFlag', () => {
    it('should return default value when Firebase getValue fails', async () => {
      mockRemoteConfig.getValue.mockImplementation(() => {
        throw new Error('Firebase error');
      });

      const result = await getFeatureFlag('test_feature', true);
      expect(result).toBe(true);
    });

    it('should return local override value when present', async () => {
      const mockOverrides = {
        testFlag: 'override value',
      };

      mockAsyncStorage.getItem.mockResolvedValue(JSON.stringify(mockOverrides));

      const result = await getFeatureFlag('testFlag', 'default value');
      expect(result).toBe('override value');
    });

    it('should return default value for string flags when not set remotely', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => '',
        asBoolean: () => false,
        asNumber: () => 0,
        getSource: () => 'default',
      });

      const result = await getFeatureFlag('testFlag', 'default value');
      expect(result).toBe('default value');
    });

    it('should return remote value for string flags when set remotely', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => 'remote value',
        asBoolean: () => false,
        asNumber: () => 0,
        getSource: () => 'remote',
      });

      const result = await getFeatureFlag('testFlag', 'default value');
      expect(result).toBe('remote value');
    });

    it('should return an explicit empty remote string (used to hide optional copy)', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => '',
        asBoolean: () => false,
        asNumber: () => 0,
        getSource: () => 'remote',
      });

      const result = await getFeatureFlag('testFlag', 'default value');
      expect(result).toBe('');
    });

    it('should preserve type for number flags', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => '42',
        asBoolean: () => false,
        asNumber: () => 42,
        getSource: () => 'remote',
      });

      const result = await getFeatureFlag('testFlag', 42);
      expect(result).toBe(42);
      expect(typeof result).toBe('number');
    });

    it('should preserve type for boolean flags', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => 'true',
        asBoolean: () => true,
        asNumber: () => 1,
        getSource: () => 'remote',
      });

      const result = await getFeatureFlag('testFlag', true);
      expect(result).toBe(true);
      expect(typeof result).toBe('boolean');
    });

    it('should prioritize local overrides over remote config', async () => {
      const mockOverrides = {
        testFlag: 'local override',
      };

      mockAsyncStorage.getItem.mockResolvedValue(JSON.stringify(mockOverrides));
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => 'remote value',
        asBoolean: () => false,
        asNumber: () => 0,
        getSource: () => 'remote',
      });

      const result = await getFeatureFlag('testFlag', 'default value');
      expect(result).toBe('local override');

      // Remote config should not be called when local override exists
      expect(mockRemoteConfig.getValue).not.toHaveBeenCalled();
    });
  });

  describe('readFeatureFlag', () => {
    it('rejects instead of returning the default when the read fails', async () => {
      mockRemoteConfig.getValue.mockImplementation(() => {
        throw new Error('Firebase error');
      });

      await expect(readFeatureFlag('test_feature', true)).rejects.toThrow(
        'Firebase error',
      );
    });

    it('rejects when the override storage read fails', async () => {
      mockAsyncStorage.getItem.mockRejectedValue(new Error('disk'));

      await expect(readFeatureFlag('test_feature', true)).rejects.toThrow(
        'disk',
      );
      await expect(getFeatureFlag('test_feature', true)).resolves.toBe(true);
    });

    it('treats corrupt override JSON as no overrides and clears it', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{not json');
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => 'true',
        asBoolean: () => true,
        asNumber: () => 1,
        getSource: () => 'remote',
      });

      await expect(readFeatureFlag('test_feature', false)).resolves.toBe(true);
      expect(mockAsyncStorage.removeItem).toHaveBeenCalledWith(
        'feature_flag_overrides',
      );
    });

    it('resolves the same value as getFeatureFlag on success', async () => {
      mockRemoteConfig.getValue.mockReturnValue({
        asString: () => 'remote value',
        asBoolean: () => false,
        asNumber: () => 0,
        getSource: () => 'remote',
      });

      await expect(readFeatureFlag('testFlag', 'default')).resolves.toBe(
        'remote value',
      );
    });
  });

  describe('getAllFeatureFlags', () => {
    it('should return empty array when Firebase getAll fails', async () => {
      mockRemoteConfig.getAll.mockImplementation(() => {
        throw new Error('Firebase error');
      });

      const result = await getAllFeatureFlags();
      expect(result).toEqual([]);
    });

    it('should return complete feature flag structure', async () => {
      // Reset all mocks to clean state
      jest.clearAllMocks();

      const mockRemoteFlags = {
        testFlag: {
          asString: () => 'test value',
          asBoolean: () => false,
          asNumber: () => 0,
          getSource: () => 'remote' as const,
        },
      };

      const mockLocalOverrides = {
        testFlag: 'overridden value',
        localOnlyFlag: 'local only',
      };

      // Configure mocks
      mockRemoteConfig.getAll.mockReturnValue(mockRemoteFlags);
      mockAsyncStorage.getItem.mockResolvedValue(
        JSON.stringify(mockLocalOverrides),
      );

      const result = await getAllFeatureFlags();

      // Check that the function returns an array
      expect(Array.isArray(result)).toBe(true);

      // Check that each flag has the expected structure
      result.forEach(flag => {
        expect(flag).toHaveProperty('key');
        expect(flag).toHaveProperty('value');
        expect(flag).toHaveProperty('type');
        expect(flag).toHaveProperty('source');
        expect(flag).toHaveProperty('remoteValue');
        expect(flag).toHaveProperty('overrideValue');
        expect(['boolean', 'string', 'number']).toContain(flag.type);
      });
    });

    it('should return correct flag values with overrides', async () => {
      const mockRemoteFlags = {
        test_flag: {
          asString: () => 'test value',
          asBoolean: () => false,
          asNumber: () => 0,
          getSource: () => 'remote' as const,
        },
      };

      const mockLocalOverrides = {};

      // Configure mocks
      mockRemoteConfig.getAll.mockReturnValue(mockRemoteFlags);
      mockRemoteConfig.getValue.mockReturnValue(mockRemoteFlags.test_flag);
      mockAsyncStorage.getItem.mockResolvedValue(
        JSON.stringify(mockLocalOverrides),
      );

      const result = await getAllFeatureFlags();

      expect(result).toEqual([
        {
          key: 'test_flag',
          value: 'test value',
          source: 'Remote Config',
          type: 'string',
          remoteValue: 'test value',
          overrideValue: undefined,
        },
      ]);
    });

    it('should return correct flag values with local overrides', async () => {
      const mockRemoteFlags = {
        test_flag: {
          asString: () => 'true',
          asBoolean: () => true,
          asNumber: () => 1,
          getSource: () => 'remote' as const,
        },
      };

      const mockLocalOverrides = {
        test_flag: false,
      };

      // Configure mocks
      mockRemoteConfig.getAll.mockReturnValue(mockRemoteFlags);
      mockRemoteConfig.getValue.mockReturnValue(mockRemoteFlags.test_flag);
      mockAsyncStorage.getItem.mockResolvedValue(
        JSON.stringify(mockLocalOverrides),
      );

      const result = await getAllFeatureFlags();

      expect(result).toEqual([
        {
          key: 'test_flag',
          value: false,
          source: 'Local Override',
          type: 'boolean',
          remoteValue: 'true',
          overrideValue: false,
        },
      ]);
    });

    it('should handle local-only flags correctly', async () => {
      const mockRemoteFlags = {};

      const mockLocalOverrides = {
        local_only_flag: 'local value',
      };

      // Configure mocks
      mockRemoteConfig.getAll.mockReturnValue(mockRemoteFlags);
      mockAsyncStorage.getItem.mockResolvedValue(
        JSON.stringify(mockLocalOverrides),
      );

      const result = await getAllFeatureFlags();

      expect(result).toEqual([
        {
          key: 'local_only_flag',
          value: 'local value',
          source: 'Local Override',
          type: 'string',
          remoteValue: undefined,
          overrideValue: 'local value',
        },
      ]);
    });
  });

  describe('Local Override Management', () => {
    it('should store and retrieve mixed types correctly', async () => {
      const mockOverrides = {
        stringFlag: 'hello world',
        booleanFlag: true,
        numberFlag: 42,
      };

      mockAsyncStorage.getItem.mockResolvedValue(JSON.stringify(mockOverrides));

      const result = await getLocalOverrides();
      expect(result).toEqual(mockOverrides);
    });

    it('should set local override for string values', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');

      await setLocalOverride('testString', 'hello world');

      expect(mockAsyncStorage.setItem).toHaveBeenCalledWith(
        'feature_flag_overrides',
        JSON.stringify({ testString: 'hello world' }),
      );
    });

    it('should set local override for number values', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');

      await setLocalOverride('testNumber', 123);

      expect(mockAsyncStorage.setItem).toHaveBeenCalledWith(
        'feature_flag_overrides',
        JSON.stringify({ testNumber: 123 }),
      );
    });

    it('should set local override for boolean values', async () => {
      mockAsyncStorage.getItem.mockResolvedValue('{}');

      await setLocalOverride('testBoolean', true);

      expect(mockAsyncStorage.setItem).toHaveBeenCalledWith(
        'feature_flag_overrides',
        JSON.stringify({ testBoolean: true }),
      );
    });

    it('should clear specific local override', async () => {
      const mockOverrides = {
        flag1: 'value1',
        flag2: 'value2',
      };

      mockAsyncStorage.getItem.mockResolvedValue(JSON.stringify(mockOverrides));

      await clearLocalOverride('flag1');

      expect(mockAsyncStorage.setItem).toHaveBeenCalledWith(
        'feature_flag_overrides',
        JSON.stringify({ flag2: 'value2' }),
      );
    });

    it('should clear all local overrides', async () => {
      await clearAllLocalOverrides();

      expect(mockAsyncStorage.removeItem).toHaveBeenCalledWith(
        'feature_flag_overrides',
      );
    });

    it('should handle AsyncStorage errors gracefully', async () => {
      mockAsyncStorage.getItem.mockRejectedValue(new Error('Storage error'));

      const result = await getLocalOverrides();
      expect(result).toEqual({});
    });

    it('should clear AsyncStorage entry when JSON parsing fails', async () => {
      // Mock AsyncStorage.getItem to return invalid JSON
      mockAsyncStorage.getItem.mockResolvedValue('invalid JSON {');

      const result = await getLocalOverrides();

      // Should call removeItem to clear the corrupt data
      expect(mockAsyncStorage.removeItem).toHaveBeenCalledWith(
        'feature_flag_overrides',
      );

      // Should return empty object
      expect(result).toEqual({});
    });
  });
  describe('subscribeToRemoteConfig', () => {
    it('notifies subscribers after init, refresh and local override changes', async () => {
      mockRemoteConfig.fetchAndActivate.mockResolvedValue(true);
      const listener = jest.fn();
      const unsubscribe = subscribeToRemoteConfig(listener);

      await initRemoteConfig();
      // Once for the cached activation, once after the fetch.
      expect(listener).toHaveBeenCalledTimes(2);

      await refreshRemoteConfig();
      expect(listener).toHaveBeenCalledTimes(3);

      await setLocalOverride('someFlag', true);
      expect(listener).toHaveBeenCalledTimes(4);

      await clearLocalOverride('someFlag');
      expect(listener).toHaveBeenCalledTimes(5);

      await clearAllLocalOverrides();
      expect(listener).toHaveBeenCalledTimes(6);

      unsubscribe();
      await refreshRemoteConfig();
      expect(listener).toHaveBeenCalledTimes(6);
    });

    it('still notifies when the remote fetch fails', async () => {
      mockRemoteConfig.fetchAndActivate.mockRejectedValue(new Error('offline'));
      const listener = jest.fn();
      const unsubscribe = subscribeToRemoteConfig(listener);
      listener.mockClear();

      await initRemoteConfig();

      expect(listener).toHaveBeenCalledTimes(2);
      unsubscribe();
    });

    it('publishes cached values before the network fetch resolves', async () => {
      let resolveFetch: (value: boolean) => void = () => {};
      mockRemoteConfig.fetchAndActivate.mockImplementation(
        () => new Promise<boolean>(resolve => (resolveFetch = resolve)),
      );
      const listener = jest.fn();
      const unsubscribe = subscribeToRemoteConfig(listener);
      listener.mockClear();

      const init = initRemoteConfig();
      await new Promise(resolve => setTimeout(resolve, 0));
      expect(listener).toHaveBeenCalledTimes(1);

      resolveFetch(true);
      await init;
      expect(listener).toHaveBeenCalledTimes(2);
      unsubscribe();
    });

    it('runs a late subscriber immediately once remote config is initialized', async () => {
      mockRemoteConfig.fetchAndActivate.mockResolvedValue(true);
      await initRemoteConfig();

      const listener = jest.fn();
      const unsubscribe = subscribeToRemoteConfig(listener);

      expect(listener).toHaveBeenCalledTimes(1);
      unsubscribe();
    });
  });
  describe('realtime updates', () => {
    type RealtimeListener = (
      event?: { updatedKeys: string[] },
      error?: Error,
    ) => Promise<void> | void;

    const captureRealtimeListener = () => {
      let captured: RealtimeListener | undefined;
      const unsubscribe = jest.fn();
      mockRemoteConfig.onConfigUpdated.mockImplementation(
        (listener: RealtimeListener) => {
          captured = listener;
          return unsubscribe;
        },
      );
      return { getListener: () => captured!, unsubscribe };
    };

    it('subscribes on init and activates then notifies on a pushed update', async () => {
      mockRemoteConfig.fetchAndActivate.mockResolvedValue(true);
      mockRemoteConfig.activate.mockResolvedValue(true);
      const { getListener } = captureRealtimeListener();
      const listener = jest.fn();
      const unsubscribe = subscribeToRemoteConfig(listener);
      listener.mockClear();

      await initRemoteConfig();
      expect(mockRemoteConfig.onConfigUpdated).toHaveBeenCalledTimes(1);
      listener.mockClear();

      await getListener()({ updatedKeys: ['kyc_flow_enabled'] });

      expect(mockRemoteConfig.activate).toHaveBeenCalledTimes(1);
      expect(listener).toHaveBeenCalledTimes(1);
      unsubscribe();
    });

    it('does not activate or notify when the realtime stream errors', async () => {
      mockRemoteConfig.fetchAndActivate.mockResolvedValue(true);
      const { getListener } = captureRealtimeListener();
      const listener = jest.fn();
      const unsubscribe = subscribeToRemoteConfig(listener);

      await initRemoteConfig();
      listener.mockClear();

      await getListener()(undefined, new Error('stream closed'));

      expect(mockRemoteConfig.activate).not.toHaveBeenCalled();
      expect(listener).not.toHaveBeenCalled();
      unsubscribe();
    });

    it('replaces the previous realtime subscription when init runs again', async () => {
      mockRemoteConfig.fetchAndActivate.mockResolvedValue(true);
      const { unsubscribe } = captureRealtimeListener();

      await initRemoteConfig();
      await initRemoteConfig();

      expect(unsubscribe).toHaveBeenCalledTimes(1);
    });
  });
});
