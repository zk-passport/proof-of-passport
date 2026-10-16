// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

/* global jest */
/** @jest-environment jsdom */

// Set up Buffer globally for tests that need it
const { Buffer } = require('buffer');

global.Buffer = Buffer;

// Mirror the globals react-native/jest/setup.js sets, since this config doesn't use
// the RN jest preset. IS_REACT_NATIVE_TEST_ENVIRONMENT suppresses React 19's
// react-test-renderer deprecation warning; IS_REACT_ACT_ENVIRONMENT marks this as a
// configured act() environment so direct react-test-renderer usage (and RNTL's
// renderHook/act) don't warn "not configured to support act(...)".
global.IS_REACT_NATIVE_TEST_ENVIRONMENT = true;
global.IS_REACT_ACT_ENVIRONMENT = true;

// Mock React Native PixelRatio globally before anything else loads
const mockPixelRatio = {
  get: jest.fn(() => 2),
  getFontScale: jest.fn(() => 1),
  getPixelSizeForLayoutSize: jest.fn(layoutSize => layoutSize * 2),
  roundToNearestPixel: jest.fn(layoutSize => Math.round(layoutSize * 2) / 2),
  startDetecting: jest.fn(),
};

global.PixelRatio = mockPixelRatio;

// Define NativeModules early so it's available for react-native mock
// This will be assigned to global.NativeModules later, but we define it here
// so the react-native mock can reference it
const NativeModules = {
  PassportReader: {
    configure: jest.fn(),
    scanPassport: jest.fn(),
    trackEvent: jest.fn(),
    flush: jest.fn(),
  },
  ReactNativeBiometrics: {
    isSensorAvailable: jest.fn().mockResolvedValue({
      available: true,
      biometryType: 'TouchID',
    }),
    createKeys: jest.fn().mockResolvedValue({ publicKey: 'mock-public-key' }),
    deleteKeys: jest.fn().mockResolvedValue(true),
    createSignature: jest
      .fn()
      .mockResolvedValue({ signature: 'mock-signature' }),
    simplePrompt: jest.fn().mockResolvedValue({ success: true }),
  },
  NativeLoggerBridge: {
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
  RNPassportReader: {
    configure: jest.fn(),
    scanPassport: jest.fn(),
    trackEvent: jest.fn(),
    flush: jest.fn(),
    reset: jest.fn(),
  },
};

// Assign to global so it's available everywhere
global.NativeModules = NativeModules;

// Mock react-native comprehensively - single source of truth for all tests
// Note: NativeModules will be defined later and assigned to global.NativeModules
// This mock accesses it at runtime via global.NativeModules
jest.mock('react-native', () => {
  // Create AppState mock with listener tracking
  // Expose listeners array globally so tests can access it
  const appStateListeners = [];
  global.mockAppStateListeners = appStateListeners;

  const mockAppState = {
    currentState: 'active',
    addEventListener: jest.fn((eventType, handler) => {
      appStateListeners.push(handler);
      return {
        remove: () => {
          const index = appStateListeners.indexOf(handler);
          if (index >= 0) {
            appStateListeners.splice(index, 1);
          }
        },
      };
    }),
  };

  return {
    __esModule: true,
    AppState: mockAppState,
    Platform: {
      OS: 'ios',
      select: jest.fn(obj => obj.ios || obj.default),
      Version: 14,
    },
    // NativeModules is defined above and assigned to global.NativeModules
    // Use getter to access it at runtime (jest.mock is hoisted)
    get NativeModules() {
      return global.NativeModules || {};
    },
    useColorScheme: jest.fn(() => 'light'),
    NativeEventEmitter: jest.fn().mockImplementation(nativeModule => {
      return {
        addListener: jest.fn(),
        removeListener: jest.fn(),
        removeAllListeners: jest.fn(),
        emit: jest.fn(),
      };
    }),
    PixelRatio: mockPixelRatio,
    Dimensions: {
      get: jest.fn(dimension => {
        const dimensions = {
          window: { width: 375, height: 667, scale: 2, fontScale: 1 },
          screen: { width: 375, height: 667, scale: 2, fontScale: 1 },
        };
        return dimension ? dimensions[dimension] : dimensions;
      }),
      addEventListener: jest.fn(() => ({ remove: jest.fn() })),
      removeEventListener: jest.fn(),
    },
    Linking: {
      getInitialURL: jest.fn().mockResolvedValue(null),
      addEventListener: jest.fn(() => ({ remove: jest.fn() })),
      removeEventListener: jest.fn(),
      openURL: jest.fn().mockResolvedValue(undefined),
      canOpenURL: jest.fn().mockResolvedValue(true),
    },
    StyleSheet: {
      create: jest.fn(styles => styles),
      flatten: jest.fn(style => style),
      hairlineWidth: 1,
      absoluteFillObject: {
        position: 'absolute',
        left: 0,
        right: 0,
        top: 0,
        bottom: 0,
      },
    },
    View: 'View',
    Text: 'Text',
    ScrollView: 'ScrollView',
    TouchableOpacity: 'TouchableOpacity',
    TouchableHighlight: 'TouchableHighlight',
    Pressable: 'Pressable',
    Image: 'Image',
    ActivityIndicator: 'ActivityIndicator',
    SafeAreaView: 'SafeAreaView',
    requireNativeComponent: jest.fn(name => {
      // Return a mock component function for any native component
      const MockNativeComponent = jest.fn(props => props.children || null);
      MockNativeComponent.displayName = `Mock(${name})`;
      return MockNativeComponent;
    }),
    codegenNativeComponent: jest.fn(() => {
      const MockNativeComponent = jest.fn(props => props.children || null);
      MockNativeComponent.displayName = 'Mock(CodegenNativeComponent)';
      return MockNativeComponent;
    }),
    codegenNativeCommands: jest.fn(() => ({})),
  };
});

require('react-native-gesture-handler/jestSetup');

jest.mock(
  'react-native/Libraries/Utilities/codegenNativeComponent',
  () => ({
    __esModule: true,
    default: jest.fn(() => {
      const MockNativeComponent = jest.fn(props => props.children || null);
      MockNativeComponent.displayName = 'Mock(CodegenNativeComponent)';
      return MockNativeComponent;
    }),
  }),
  { virtual: true },
);

jest.mock(
  'react-native/Libraries/Utilities/codegenNativeCommands',
  () => ({
    __esModule: true,
    default: jest.fn(() => ({})),
  }),
  { virtual: true },
);

// Mock NativeAnimatedHelper - using virtual mock during RN 0.76.9 prep phase
jest.mock(
  'react-native/src/private/animated/NativeAnimatedHelper',
  () => ({}),
  { virtual: true },
);

// Mock React Native bridge config for mobile-sdk-alpha components
global.__fbBatchedBridgeConfig = {
  messageQueue: {
    SPY_MODE: false,
  },
  remoteModuleConfig: [],
};

// Set up global React Native test environment
global.__DEV__ = true;

// Set up global mock navigation ref for tests
global.mockNavigationRef = {
  isReady: jest.fn(() => true),
  getCurrentRoute: jest.fn(() => ({ name: 'Home' })),
  navigate: jest.fn(),
  goBack: jest.fn(),
  canGoBack: jest.fn(() => true),
  dispatch: jest.fn(),
  getState: jest.fn(() => ({ routes: [{ name: 'Home' }], index: 0 })),
  addListener: jest.fn(() => jest.fn()),
  removeListener: jest.fn(),
};

// Load grouped mocks
require('./tests/__setup__/mocks/navigation');
require('./tests/__setup__/mocks/ui');

// Mock TurboModuleRegistry to provide required native modules for BOTH main app and mobile-sdk-alpha
jest.mock('react-native/Libraries/TurboModule/TurboModuleRegistry', () => ({
  getEnforcing: jest.fn(name => {
    if (name === 'PlatformConstants') {
      return {
        getConstants: () => ({
          reactNativeVersion: { major: 0, minor: 76, patch: 9 },
          forceTouchAvailable: false,
          osVersion: '14.0',
          systemName: 'iOS',
          interfaceIdiom: 'phone',
          Dimensions: {
            window: { width: 375, height: 667, scale: 2 },
            screen: { width: 375, height: 667, scale: 2 },
          },
        }),
      };
    }
    if (name === 'SettingsManager') {
      return {
        getConstants: () => ({}),
      };
    }
    if (name === 'DeviceInfo') {
      return {
        getConstants: () => ({
          Dimensions: {
            window: { width: 375, height: 667, scale: 2 },
            screen: { width: 375, height: 667, scale: 2 },
          },
        }),
      };
    }
    if (name === 'RNDeviceInfo') {
      return {
        getConstants: () => ({
          Dimensions: {
            window: { width: 375, height: 667, scale: 2 },
            screen: { width: 375, height: 667, scale: 2 },
          },
        }),
      };
    }
    return {
      getConstants: () => ({}),
    };
  }),
  get: jest.fn(() => null),
}));

// Mock main React Native PixelRatio module
jest.mock('react-native/Libraries/Utilities/PixelRatio', () => ({
  get: jest.fn(() => 2),
  getFontScale: jest.fn(() => 1),
  getPixelSizeForLayoutSize: jest.fn(layoutSize => layoutSize * 2),
  roundToNearestPixel: jest.fn(layoutSize => Math.round(layoutSize * 2) / 2),
  startDetecting: jest.fn(),
}));

// Mock mobile-sdk-alpha to use the main React Native instance instead of its own
jest.mock(
  '../packages/mobile-sdk-alpha/node_modules/react-native',
  () => {
    // Create the PixelRatio mock first
    const PixelRatio = {
      get: jest.fn(() => 2),
      getFontScale: jest.fn(() => 1),
      getPixelSizeForLayoutSize: jest.fn(layoutSize => layoutSize * 2),
      roundToNearestPixel: jest.fn(
        layoutSize => Math.round(layoutSize * 2) / 2,
      ),
      startDetecting: jest.fn(),
    };

    // Return a simple object with all the mocks we need
    // Avoid nested requireActual/requireMock to prevent OOM in CI
    return {
      __esModule: true,
      PixelRatio,
      Platform: {
        OS: 'ios',
        select: jest.fn(obj => obj.ios || obj.default),
        Version: 14,
      },
      Dimensions: {
        get: jest.fn(dimension => {
          const dimensions = {
            window: { width: 375, height: 667, scale: 2, fontScale: 1 },
            screen: { width: 375, height: 667, scale: 2, fontScale: 1 },
          };
          return dimension ? dimensions[dimension] : dimensions;
        }),
        addEventListener: jest.fn(() => ({ remove: jest.fn() })),
        removeEventListener: jest.fn(),
      },
      StyleSheet: {
        create: jest.fn(styles => styles),
        flatten: jest.fn(style => style),
        hairlineWidth: 1,
        absoluteFillObject: {
          position: 'absolute',
          left: 0,
          right: 0,
          top: 0,
          bottom: 0,
        },
      },
      View: 'View',
      Text: 'Text',
      ScrollView: 'ScrollView',
      TouchableOpacity: 'TouchableOpacity',
      requireNativeComponent: jest.fn(name => {
        const MockNativeComponent = jest.fn(props => props.children || null);
        MockNativeComponent.displayName = `Mock(${name})`;
        return MockNativeComponent;
      }),
    };
  },
  { virtual: true },
);

// Mock @turnkey/react-native-wallet-kit to prevent loading of problematic dependencies
jest.mock(
  '@turnkey/react-native-wallet-kit',
  () => ({
    AuthState: {
      Authenticated: 'Authenticated',
      Unauthenticated: 'Unauthenticated',
    },
    useTurnkey: jest.fn(() => ({
      handleGoogleOauth: jest.fn(),
      fetchWallets: jest.fn().mockResolvedValue([]),
      exportWallet: jest.fn(),
      importWallet: jest.fn(),
      authState: 'Unauthenticated',
      logout: jest.fn(),
    })),
    TurnkeyProvider: ({ children }) => children,
  }),
  { virtual: true },
);

// Mock the mobile-sdk-alpha's TurboModuleRegistry to prevent native module errors
jest.mock(
  '../packages/mobile-sdk-alpha/node_modules/react-native/Libraries/TurboModule/TurboModuleRegistry',
  () => ({
    getEnforcing: jest.fn(name => {
      if (name === 'PlatformConstants') {
        return {
          getConstants: () => ({
            reactNativeVersion: { major: 0, minor: 76, patch: 9 },
            forceTouchAvailable: false,
            osVersion: '14.0',
            systemName: 'iOS',
            interfaceIdiom: 'phone',
            Dimensions: {
              window: { width: 375, height: 667, scale: 2 },
              screen: { width: 375, height: 667, scale: 2 },
            },
          }),
        };
      }
      return {
        getConstants: () => ({}),
      };
    }),
    get: jest.fn(() => null),
  }),
  { virtual: true },
);

// Mock mobile-sdk-alpha's Dimensions module
jest.mock(
  '../packages/mobile-sdk-alpha/node_modules/react-native/Libraries/Utilities/Dimensions',
  () => ({
    getConstants: jest.fn(() => ({
      window: { width: 375, height: 667, scale: 2, fontScale: 1 },
      screen: { width: 375, height: 667, scale: 2, fontScale: 1 },
    })),
    set: jest.fn(),
    get: jest.fn(dimension => {
      const dimensions = {
        window: { width: 375, height: 667, scale: 2, fontScale: 1 },
        screen: { width: 375, height: 667, scale: 2, fontScale: 1 },
      };
      return dimension ? dimensions[dimension] : dimensions;
    }),
    addEventListener: jest.fn(() => ({ remove: jest.fn() })),
    removeEventListener: jest.fn(),
  }),
  { virtual: true },
);

// Mock mobile-sdk-alpha's PixelRatio module directly since it's still needed by StyleSheet
jest.mock(
  '../packages/mobile-sdk-alpha/node_modules/react-native/Libraries/Utilities/PixelRatio',
  () => ({
    get: jest.fn(() => 2),
    getFontScale: jest.fn(() => 1),
    getPixelSizeForLayoutSize: jest.fn(layoutSize => layoutSize * 2),
    roundToNearestPixel: jest.fn(layoutSize => Math.round(layoutSize * 2) / 2),
    startDetecting: jest.fn(),
  }),
  { virtual: true },
);

// Mock mobile-sdk-alpha's StyleSheet module directly since it's still needed
jest.mock(
  '../packages/mobile-sdk-alpha/node_modules/react-native/Libraries/StyleSheet/StyleSheet',
  () => ({
    create: jest.fn(styles => styles),
    flatten: jest.fn(style => style),
    hairlineWidth: 1,
    absoluteFillObject: {
      position: 'absolute',
      left: 0,
      right: 0,
      top: 0,
      bottom: 0,
    },
    roundToNearestPixel: jest.fn(layoutSize => Math.round(layoutSize * 2) / 2),
  }),
  { virtual: true },
);

// Mock main React Native StyleSheet module
jest.mock('react-native/Libraries/StyleSheet/StyleSheet', () => ({
  create: jest.fn(styles => styles),
  flatten: jest.fn(style => style),
  hairlineWidth: 1,
  absoluteFillObject: {
    position: 'absolute',
    left: 0,
    right: 0,
    top: 0,
    bottom: 0,
  },
  roundToNearestPixel: jest.fn(layoutSize => Math.round(layoutSize * 2) / 2),
}));

// Mock NativeDeviceInfo specs for both main app and mobile-sdk-alpha
jest.mock(
  'react-native/src/private/specs_DEPRECATED/modules/NativeDeviceInfo',
  () => ({
    getConstants: jest.fn(() => ({
      Dimensions: {
        window: { width: 375, height: 667, scale: 2 },
        screen: { width: 375, height: 667, scale: 2 },
      },
    })),
  }),
  { virtual: true },
);

// Mock NativeStatusBarManagerIOS for react-native-edge-to-edge SystemBars
jest.mock(
  'react-native/src/private/specs_DEPRECATED/modules/NativeStatusBarManagerIOS',
  () => ({
    setStyle: jest.fn(),
    setHidden: jest.fn(),
    setNetworkActivityIndicatorVisible: jest.fn(),
  }),
  { virtual: true },
);

// Mock react-native-gesture-handler to prevent getConstants errors
jest.mock('react-native-gesture-handler', () => {
  // Avoid requiring React to prevent nested require memory issues

  // Mock the components as simple pass-through functions
  const MockScrollView = jest.fn(props => props.children || null);
  const MockTouchableOpacity = jest.fn(props => props.children || null);
  const MockTouchableHighlight = jest.fn(props => props.children || null);
  const MockFlatList = jest.fn(props => null);

  return {
    // Provide gesture handler mock without requireActual to avoid OOM
    GestureHandlerRootView: ({ children }) => children,
    ScrollView: MockScrollView,
    TouchableOpacity: MockTouchableOpacity,
    TouchableHighlight: MockTouchableHighlight,
    FlatList: MockFlatList,
    Directions: {},
    State: {},
    Swipeable: jest.fn(() => null),
    DrawerLayout: jest.fn(() => null),
    PanGestureHandler: jest.fn(() => null),
    TapGestureHandler: jest.fn(() => null),
    LongPressGestureHandler: jest.fn(() => null),
  };
});

// Mock react-native-safe-area-context
jest.mock('react-native-safe-area-context', () => {
  // Avoid requiring React to prevent nested require memory issues
  return {
    __esModule: true,
    SafeAreaProvider: jest.fn(({ children }) => children || null),
    SafeAreaView: jest.fn(({ children }) => children || null),
    useSafeAreaInsets: () => ({ top: 0, bottom: 0, left: 0, right: 0 }),
  };
});

// Mock NativeEventEmitter to prevent null argument errors
jest.mock('react-native/Libraries/EventEmitter/NativeEventEmitter', () => {
  function MockNativeEventEmitter(nativeModule) {
    // Accept any nativeModule argument (including null/undefined)
    this.nativeModule = nativeModule;
    this.addListener = jest.fn();
    this.removeListener = jest.fn();
    this.removeAllListeners = jest.fn();
    this.emit = jest.fn();
  }

  // The mock needs to be the constructor itself, not wrapped
  MockNativeEventEmitter.default = MockNativeEventEmitter;
  return MockNativeEventEmitter;
});

// Mock react-native-device-info to prevent NativeEventEmitter errors
jest.mock('react-native-device-info', () => ({
  getUniqueId: jest.fn().mockResolvedValue('mock-device-id'),
  getReadableVersion: jest.fn().mockReturnValue('1.0.0'),
  getVersion: jest.fn().mockReturnValue('1.0.0'),
  getBuildNumber: jest.fn().mockReturnValue('1'),
  getModel: jest.fn().mockReturnValue('mock-model'),
  getBrand: jest.fn().mockReturnValue('mock-brand'),
  isTablet: jest.fn().mockReturnValue(false),
  isLandscape: jest.fn().mockResolvedValue(false),
  getSystemVersion: jest.fn().mockReturnValue('14.0'),
  getSystemName: jest.fn().mockReturnValue('iOS'),
  default: {
    getUniqueId: jest.fn().mockResolvedValue('mock-device-id'),
    getReadableVersion: jest.fn().mockReturnValue('1.0.0'),
    getVersion: jest.fn().mockReturnValue('1.0.0'),
    getBuildNumber: jest.fn().mockReturnValue('1'),
    getModel: jest.fn().mockReturnValue('mock-model'),
    getBrand: jest.fn().mockReturnValue('mock-brand'),
    isTablet: jest.fn().mockReturnValue(false),
    isLandscape: jest.fn().mockResolvedValue(false),
    getSystemVersion: jest.fn().mockReturnValue('14.0'),
    getSystemName: jest.fn().mockReturnValue('iOS'),
  },
}));

// Mock react-native-device-info nested in @turnkey/react-native-wallet-kit
jest.mock(
  'node_modules/@turnkey/react-native-wallet-kit/node_modules/react-native-device-info',
  () => ({
    getUniqueId: jest.fn().mockResolvedValue('mock-device-id'),
    getReadableVersion: jest.fn().mockReturnValue('1.0.0'),
    getVersion: jest.fn().mockReturnValue('1.0.0'),
    getBuildNumber: jest.fn().mockReturnValue('1'),
    getModel: jest.fn().mockReturnValue('mock-model'),
    getBrand: jest.fn().mockReturnValue('mock-brand'),
    isTablet: jest.fn().mockReturnValue(false),
    isLandscape: jest.fn().mockResolvedValue(false),
    getSystemVersion: jest.fn().mockReturnValue('14.0'),
    getSystemName: jest.fn().mockReturnValue('iOS'),
    default: {
      getUniqueId: jest.fn().mockResolvedValue('mock-device-id'),
      getReadableVersion: jest.fn().mockReturnValue('1.0.0'),
      getVersion: jest.fn().mockReturnValue('1.0.0'),
      getBuildNumber: jest.fn().mockReturnValue('1'),
      getModel: jest.fn().mockReturnValue('mock-model'),
      getBrand: jest.fn().mockReturnValue('mock-brand'),
      isTablet: jest.fn().mockReturnValue(false),
      isLandscape: jest.fn().mockResolvedValue(false),
      getSystemVersion: jest.fn().mockReturnValue('14.0'),
      getSystemName: jest.fn().mockReturnValue('iOS'),
    },
  }),
  { virtual: true },
);

// Mock the hooks subpath from mobile-sdk-alpha
jest.mock('@selfxyz/mobile-sdk-alpha/hooks', () => ({
  useSafeBottomPadding: jest.fn((basePadding = 20) => basePadding + 50),
}));

// Mock problematic mobile-sdk-alpha components that use React Native StyleSheet
jest.mock('@selfxyz/mobile-sdk-alpha', () => ({
  // Override only the specific mocks we need
  NFCScannerScreen: jest.fn(() => null),
  SelfClientProvider: jest.fn(({ children }) => children),
  useSelfClient: jest.fn(() => {
    // Create a consistent mock instance for memoization testing
    if (!global.mockSelfClientInstance) {
      global.mockSelfClientInstance = {
        // Mock selfClient object with common methods
        connect: jest.fn(),
        disconnect: jest.fn(),
        isConnected: false,
        extractMRZInfo: jest.fn(mrzString => {
          // Mock extractMRZInfo with realistic behavior
          if (!mrzString || typeof mrzString !== 'string') {
            throw new Error('Invalid MRZ string provided');
          }

          // Valid MRZ example from the test
          if (mrzString.includes('L898902C3')) {
            return {
              documentNumber: 'L898902C3',
              validation: {
                overall: true,
              },
              // Add other expected MRZ fields
              firstName: 'ANNA',
              lastName: 'ERIKSSON',
              nationality: 'UTO',
              dateOfBirth: '740812',
              sex: 'F',
              expirationDate: '120415',
            };
          }

          // For malformed/invalid MRZ strings, throw an error
          throw new Error('Invalid MRZ format');
        }),
        trackEvent: jest.fn(),
      };
    }
    return global.mockSelfClientInstance;
  }),
  createSelfClient: jest.fn(() => ({
    // Mock createSelfClient return value
    connect: jest.fn(),
    disconnect: jest.fn(),
    isConnected: false,
    extractMRZInfo: jest.fn(mrzString => {
      // Mock extractMRZInfo with realistic behavior
      if (!mrzString || typeof mrzString !== 'string') {
        throw new Error('Invalid MRZ string provided');
      }

      // Valid MRZ example from the test
      if (mrzString.includes('L898902C3')) {
        return {
          documentNumber: 'L898902C3',
          validation: {
            overall: true,
          },
          // Add other expected MRZ fields
          firstName: 'ANNA',
          lastName: 'ERIKSSON',
          nationality: 'UTO',
          dateOfBirth: '740812',
          sex: 'F',
          expirationDate: '120415',
        };
      }

      // For malformed/invalid MRZ strings, throw an error
      throw new Error('Invalid MRZ format');
    }),
    trackEvent: jest.fn(),
  })),
  createListenersMap: jest.fn(() => ({
    // Mock createListenersMap return value
    map: new Map(),
    addListener: jest.fn(),
    removeListener: jest.fn(),
  })),
  isPassportDataValid: jest.fn((data, callbacks) => {
    // Mock validation function with realistic behavior
    if (!data || !data.passportMetadata) {
      // Call appropriate callbacks for missing data
      if (callbacks?.onPassportMetadataNull) {
        callbacks.onPassportMetadataNull();
      }
      return false;
    }
    // Return true for valid data, false for invalid
    return data.valid !== false;
  }),
  SdkEvents: {
    // Mock SDK events object
    PROVING_PASSPORT_DATA_NOT_FOUND: 'PROVING_PASSPORT_DATA_NOT_FOUND',
    PROVING_STARTED: 'PROVING_STARTED',
    PROVING_COMPLETED: 'PROVING_COMPLETED',
    PROVING_FAILED: 'PROVING_FAILED',
    // Add other events as needed
  },
  // Mock haptic functions
  buttonTap: jest.fn(),
  cancelTap: jest.fn(),
  confirmTap: jest.fn(),
  feedbackProgress: jest.fn(),
  feedbackSuccess: jest.fn(),
  feedbackUnsuccessful: jest.fn(),
  impactLight: jest.fn(),
  impactMedium: jest.fn(),
  loadingScreenProgress: jest.fn(),
  notificationError: jest.fn(),
  notificationSuccess: jest.fn(),
  notificationWarning: jest.fn(),
  selectionChange: jest.fn(),
  triggerFeedback: jest.fn(),
  // Add other components and hooks as needed
}));

// Mock Sentry to prevent NativeModule.getConstants errors
jest.mock('@sentry/react-native', () => {
  const React = jest.requireActual('react');
  const passThrough = ({ children }) =>
    React.createElement(React.Fragment, null, children);
  return {
    addBreadcrumb: jest.fn(),
    captureException: jest.fn(),
    captureFeedback: jest.fn(),
    captureMessage: jest.fn(),
    consoleLoggingIntegration: jest.fn(),
    feedbackIntegration: jest.fn(),
    Mask: passThrough,
    Unmask: passThrough,
    MaskFallback: passThrough,
    UnmaskFallback: passThrough,
    mobileReplayIntegration: jest.fn(),
    setContext: jest.fn(),
    setExtra: jest.fn(),
    setTag: jest.fn(),
    setUser: jest.fn(),
    init: jest.fn(),
    wrap: jest.fn(component => component),
    withScope: jest.fn(callback => {
      const scope = {
        setLevel: jest.fn(),
        setTag: jest.fn(),
        setExtra: jest.fn(),
        setContext: jest.fn(),
        setUser: jest.fn(),
      };
      callback(scope);
    }),
  };
});

jest.mock('@react-native-google-signin/google-signin', () => ({
  GoogleSignin: {
    configure: jest.fn(),
    hasPlayServices: jest.fn().mockResolvedValue(true),
    signIn: jest.fn().mockResolvedValue({
      type: 'success',
      data: {
        user: {
          id: 'mock-google-user-id',
          name: 'Mock User',
          email: 'mock@example.com',
        },
      },
    }),
    signOut: jest.fn().mockResolvedValue(null),
    getCurrentUser: jest.fn().mockResolvedValue(null),
    getTokens: jest.fn().mockResolvedValue({ idToken: 'mock-token' }),
  },
  GoogleSigninButton: 'GoogleSigninButton',
  statusCodes: {
    SIGN_IN_CANCELLED: 'SIGN_IN_CANCELLED',
    IN_PROGRESS: 'IN_PROGRESS',
    PLAY_SERVICES_NOT_AVAILABLE: 'PLAY_SERVICES_NOT_AVAILABLE',
  },
}));

jest.mock('@invertase/react-native-apple-authentication', () => ({
  __esModule: true,
  default: {
    performRequest: jest.fn().mockResolvedValue({
      user: 'mock-apple-user-id',
      fullName: { givenName: 'Mock', familyName: 'User' },
      email: 'mock@example.com',
    }),
    getCredentialStateForUser: jest.fn().mockResolvedValue(1),
    onCredentialRevoked: jest.fn(() => jest.fn()),
    isSupported: true,
    State: { AUTHORIZED: 1 },
    Error: { CANCELED: 1001 },
  },
  AppleButton: 'AppleButton',
  AppleRequestScope: { EMAIL: 0, FULL_NAME: 1 },
  AppleRequestOperation: { LOGIN: 1 },
}));

jest.mock('@env', () => ({
  ENABLE_DEBUG_LOGS: 'false',
  GOOGLE_SIGNIN_ANDROID_CLIENT_ID: 'mock-google-client-id',
  GOOGLE_SIGNIN_IOS_CLIENT_ID: 'mock-google-ios-client-id',
  GOOGLE_SIGNIN_WEB_CLIENT_ID: 'mock-google-web-client-id',
  MIXPANEL_NFC_PROJECT_TOKEN: 'test-token',
  SENTRY_DSN: 'https://example@sentry.example/1',
}));

global.FileReader = class {
  constructor() {
    this.onload = null;
  }
  readAsArrayBuffer() {
    if (this.onload) {
      this.onload({ target: { result: new ArrayBuffer(0) } });
    }
  }
};

jest.mock('@react-native-firebase/messaging', () => {
  return () => ({
    hasPermission: jest.fn(() => Promise.resolve(true)),
    requestPermission: jest.fn(() => Promise.resolve(true)),
    getToken: jest.fn(() => Promise.resolve('mock-token')),
    onMessage: jest.fn(() => jest.fn()),
    onNotificationOpenedApp: jest.fn(() => jest.fn()),
    getInitialNotification: jest.fn(() => Promise.resolve(null)),
    setBackgroundMessageHandler: jest.fn(),
    registerDeviceForRemoteMessages: jest.fn(() => Promise.resolve()),
    subscribeToTopic: jest.fn(),
    unsubscribeFromTopic: jest.fn(),
  });
});

jest.mock('@react-native-firebase/remote-config', () => {
  const mockValue = { asBoolean: jest.fn(() => false) };
  const mockConfig = {
    setDefaults: jest.fn(),
    setConfigSettings: jest.fn(),
    fetchAndActivate: jest.fn(() => Promise.resolve(true)),
    activate: jest.fn(() => Promise.resolve(true)),
    onConfigUpdated: jest.fn(() => jest.fn()),
    getValue: jest.fn(() => mockValue),
  };
  return () => mockConfig;
});

// Mock react-native-haptic-feedback
jest.mock('react-native-haptic-feedback', () => ({
  trigger: jest.fn(),
}));

// Mock Segment Analytics
jest.mock('@segment/analytics-react-native', () => {
  const mockClient = {
    add: jest.fn(),
    track: jest.fn(),
    identify: jest.fn(),
    screen: jest.fn(),
    group: jest.fn(),
    alias: jest.fn(),
    reset: jest.fn(),
  };

  // Mock flush policy classes
  const MockFlushPolicy = class {
    constructor() {}
  };

  return {
    createClient: jest.fn(() => mockClient),
    EventPlugin: jest.fn(),
    PluginType: {
      ENRICHMENT: 'enrichment',
      DESTINATION: 'destination',
      BEFORE: 'before',
      before: 'before',
    },
    StartupFlushPolicy: MockFlushPolicy,
    BackgroundFlushPolicy: MockFlushPolicy,
  };
});

jest.mock('@selfxyz/mobile-sdk-alpha/constants/analytics', () => ({
  AadhaarEvents: {
    CONTINUE_PRESSED: 'Aadhaar: Continue Pressed',
    DATA_STORED: 'Aadhaar: Data Stored',
    PHOTO_PERMISSION_DENIED: 'Aadhaar: Photo Permission Denied',
    QR_PARSE_FAILED: 'Aadhaar: QR Parse Failed',
    QR_SELECTED: 'Aadhaar: QR Selected',
    TIMESTAMP_EXPIRED: 'Aadhaar: Timestamp Expired',
    UPLOAD_STARTED: 'Aadhaar: Upload Started',
  },
  AppEvents: {
    DISMISS_PRIVACY_DISCLAIMER: 'App: Dismiss Privacy Disclaimer',
    GET_STARTED: 'App: Get Started',
    GET_STARTED_AADHAAR: 'App: Get Started - Aadhaar',
    GET_STARTED_BIOMETRIC: 'App: Get Started - Biometric ID',
    SUPPORTED_BIOMETRIC_IDS: 'App: Supported Biometric IDs',
    UPDATE_MODAL_CLOSED: 'App: Update Modal Closed',
    UPDATE_MODAL_OPENED: 'App: Update Modal Opened',
    UPDATE_STARTED: 'App: Update Started',
  },
  AuthEvents: {
    BIOMETRIC_LOGIN_CANCELLED: 'Auth: Biometric Login Cancelled',
    BIOMETRIC_LOGIN_FAILED: 'Auth: Biometric Login Failed',
    BIOMETRIC_LOGIN_SUCCESS: 'Auth: Biometric Login Success',
  },
  BackupEvents: {
    ACCOUNT_RECOVERY_COMPLETED: 'Backup: Account Recovery Completed',
    ACCOUNT_RECOVERY_STARTED: 'Backup: Account Recovery Started',
    ACCOUNT_VERIFICATION_COMPLETED: 'Backup: Account Verification Completed',
    CLOUD_BACKUP_CANCELLED: 'Backup: Cloud Backup Cancelled',
    CLOUD_BACKUP_CONTINUE: 'Backup: Cloud Backup Continue',
    CLOUD_BACKUP_DISABLED_DONE: 'Backup: Cloud Backup Disabled Done',
    CLOUD_BACKUP_DISABLE_STARTED: 'Backup: Cloud Backup Disable Started',
    CLOUD_BACKUP_ENABLED_DONE: 'Backup: Cloud Backup Enabled Done',
    CLOUD_BACKUP_ENABLE_FAILED: 'Backup: Cloud Backup Enable Failed',
    CLOUD_BACKUP_ENABLE_STARTED: 'Backup: Cloud Backup Enable Started',
    CLOUD_BACKUP_STARTED: 'Backup: Cloud Backup Started',
    CLOUD_RESTORE_FAILED_AUTH:
      'Backup: Cloud Restore Failed: Authentication Failed',
    CLOUD_RESTORE_FAILED_PASSPORT_NOT_REGISTERED:
      'Backup: Cloud Restore Failed: Passport Not Registered',
    CLOUD_RESTORE_FAILED_UNKNOWN: 'Backup: Cloud Restore Failed: Unknown Error',
    CLOUD_RESTORE_STARTED: 'Backup: Cloud Restore Started',
    CLOUD_RESTORE_SUCCESS: 'Backup: Cloud Restore Success',
    TURNKEY_RESTORE_FAILED: 'Backup: Turnkey Restore Failed',
    CREATE_NEW_ACCOUNT: 'Backup: Create New Account',
    MANUAL_RECOVERY_SELECTED: 'Backup: Manual Recovery Selected',
  },
  BiometricEvents: {
    DOCUMENT_PARSED: 'Biometric: Document Parsed',
    DOCUMENT_UNSUPPORTED: 'Biometric: Document Unsupported',
    MRZ_CAPTURED: 'Biometric: MRZ Captured',
    MRZ_STARTED: 'Biometric: MRZ Started',
    NFC_STARTED: 'Biometric: NFC Started',
    NFC_SUCCEEDED: 'Biometric: NFC Succeeded',
    NFC_RESPONSE_PARSE_FAILED: 'Passport: Parsing NFC Response Unsuccessful',
    NFC_SCAN_FAILED: 'Passport: NFC Scan Failed',
  },
  DocumentEvents: {
    ADD_NEW_AADHAAR_SELECTED: 'Document: Add Aadhaar',
    ADD_NEW_MOCK_SELECTED: 'Document: Add New Document via Mock',
    ADD_NEW_SCAN_SELECTED: 'Document: Add New Document via Scan',
    DOCUMENT_DELETED: 'Document: Document Deleted',
    DOCUMENT_SELECTED: 'Document: Document Selected',
    DOCUMENT_VALIDATED: 'Document: Document Validated',
    DOCUMENTS_FETCHED: 'Document: Documents Fetched',
    MANAGE_SCREEN_OPENED: 'Document: Manage Documents Screen Opened',
    NO_DOCUMENTS_FOUND: 'Document: No Documents Found',
    PASSPORT_INFO_OPENED: 'Document: Passport Info Screen Opened',
    PASSPORT_METADATA_LOADED: 'Document: Passport Metadata Loaded',
    VALIDATE_DOCUMENT_FAILED: 'Document: Validate Document Failed',
  },
  IDDataEvents: {
    PERKS_VIEWED: 'ID Data: Perks Viewed',
    PERK_TAPPED: 'ID Data: Perk Tapped',
    PERK_OUTLINK_OPEN_FAILED: 'ID Data: Perk Outlink Open Failed',
  },
  HomescreenEvents: {
    ID_CARD_VIEWED: 'Homescreen: ID Card Viewed',
    ID_CARD_PERK_TAPPED: 'Homescreen: ID Card Perk Tapped',
    ID_CARD_PERK_OUTLINK_OPEN_FAILED:
      'Homescreen: ID Card Perk Outlink Open Failed',
  },
  KycEvents: {
    PROVIDER_CLOSED: 'KYC: Provider Closed',
    PROVIDER_OPENED: 'KYC: Provider Opened',
    RETRY_TRIGGERED: 'KYC: Retry Triggered',
    SESSION_CREATED: 'KYC: Session Created',
    SESSION_REQUESTED: 'KYC: Session Requested',
    VERIFICATION_RESOLVED: 'KYC: Verification Resolved',
  },
  MockDataEvents: {
    CANCEL_GENERATION: 'Mock Data: Cancel Generation',
    CREATE_DEEP_LINK: 'Mock Data: Create Deep Link',
    DECREASE_AGE: 'Mock Data: Decrease Age',
    DECREASE_EXPIRY_YEARS: 'Mock Data: Decrease Expiry Years',
    ENABLE_ADVANCED_MODE: 'Mock Data: Enable Advanced Mode',
    GENERATE_DATA: 'Mock Data: Generate Data',
    INCREASE_AGE: 'Mock Data: Increase Age',
    INCREASE_EXPIRY_YEARS: 'Mock Data: Increase Expiry Years',
    OPEN_ALGORITHM_SELECTION: 'Mock Data: Open Algorithm Selection',
    OPEN_COUNTRY_SELECTION: 'Mock Data: Open Country Selection',
    SELECT_ALGORITHM: 'Mock Data: Select Algorithm',
    SELECT_COUNTRY: 'Mock Data: Select Country',
    SELECT_DOCUMENT_TYPE: 'Mock Data: Select Document Type',
    TOGGLE_OFAC_LIST: 'Mock Data: Toggle OFAC List',
  },
  NotificationEvents: {
    BACKGROUND_NOTIFICATION_OPENED:
      'Notification: Background Notification Opened',
    COLD_START_NOTIFICATION_OPENED:
      'Notification: Cold Start Notification Opened',
  },
  OnboardingEvents: {
    STARTED: 'Onboarding: Started',
    COUNTRY_SELECTED: 'Onboarding: Country Selected',
    DOCUMENT_TYPE_SELECTED: 'Onboarding: Document Type Selected',
    SCAN_STARTED: 'Onboarding: Document Scan Started',
    SCAN_SUCCEEDED: 'Onboarding: Document Scan Succeeded',
    PROOF_STARTED: 'Onboarding: Proof Generation Started',
    PROOF_SUCCEEDED: 'Onboarding: Proof Generation Succeeded',
    ENDED: 'Onboarding: Ended',
    STEP_RETRIED: 'Onboarding: Step Retried',
  },
  PointEvents: {
    HOME_POINT_EARN_POINTS_OPENED: 'Points: Home Earn Points Opened',
    EXPLORE_APPS: 'Points: Explore Apps Opened',
    EARN_REFERRAL: 'Points: Earn Referral Opened',
    EARN_REFERRAL_MESSAGES: 'Points: Earn Referral via Messages',
    EARN_REFERRAL_WHATSAPP: 'Points: Earn Referral via WhatsApp',
    EARN_REFERRAL_SHARE: 'Points: Earn Referral via Share',
    EARN_REFERRAL_COPY_LINK: 'Points: Earn Referral Copy Link',
    EARN_BACKUP: 'Points: Earn with Backup',
    EARN_BACKUP_SUCCESS: 'Points: Earn with Backup Success',
    EARN_BACKUP_FAILED: 'Points: Earn with Backup Failed',
    EARN_NOTIFICATION: 'Points: Earn with Notification',
    EARN_NOTIFICATION_FAILED: 'Points: Earn with Notification Failed',
    EARN_NOTIFICATION_SUCCESS: 'Points: Earn with Notification Success',
    REFRESH_HISTORY: 'Points: Refresh History',
  },
  ProofEvents: {
    ALREADY_REGISTERED: 'Proof: Already Registered',
    ATTESTATION_RECEIVED: 'Proof: Attestation Received',
    ATTESTATION_VERIFIED: 'Proof: Attestation Verified',
    CLEANUP_COMPLETED: 'Proof: Connections Cleanup Completed',
    CLEANUP_STARTED: 'Proof: Connections Cleanup Started',
    CONNECTION_UUID_GENERATED: 'Proof: Connection UUID Generated',
    DEVICE_TOKEN_REG_FAILED: 'Proof: Device Token Registration Failed',
    DEVICE_TOKEN_REG_STARTED: 'Proof: Device Token Registration Started',
    DEVICE_TOKEN_REG_SUCCESS: 'Proof: Device Token Registration Succeeded',
    DOCUMENT_LOAD_STARTED: 'Proof: Load Selected Document Started',
    DSC_IN_TREE: 'Proof: DSC Already In Tree',
    FCM_TOKEN_STORED: 'Proof: FCM Token Stored Successfully',
    FETCH_DATA_FAILED: 'Proof: Fetch Data Failed',
    FETCH_DATA_STARTED: 'Proof: Fetch Data Started',
    FETCH_DATA_SUCCESS: 'Proof: Fetch Data Succeeded',
    GOOGLE_USAT_BLOCK_DISMISSED:
      'Proof: Google USAT Disclosure Block Dismissed',
    GOOGLE_USAT_BLOCKED: 'Proof: Google USAT Disclosure Blocked',
    GOOGLE_USAT_RECOVER_CLICKED:
      'Proof: Google USAT Disclosure Recover Clicked',
    LOAD_SECRET_FAILED: 'Proof: Load Secret Failed',
    PARSE_ID_DOCUMENT_STARTED: 'Proof: Parse ID Document Started',
    NOTIFICATION_PERMISSION_REQUESTED:
      'Proof: Notification Permission Requested',
    PASSPORT_NULLIFIER_ONCHAIN: 'Proof: Passport Nullifier Onchain',
    PAYLOAD_ENCRYPTED: 'Proof: Payload Encrypted',
    PAYLOAD_GEN_COMPLETED: 'Proof: Payload Generation Completed',
    PAYLOAD_GEN_STARTED: 'Proof: Payload Generation Started',
    PAYLOAD_SENT: 'Proof: Payload Sent',
    POST_PROVING_CHAIN_STEP: 'Proof: Post Proving Chain Step',
    POST_PROVING_COMPLETED: 'Proof: Post Proving Completed',
    POST_PROVING_STARTED: 'Proof: Post Proving Started',
    PROOF_COMPLETED: 'Proof: Proof Completed',
    PROOF_DISCLOSURES_SCROLLED: 'Proof: Proof Disclosures Scrolled',
    PROOF_FAILED: 'Proof: Proof Failed',
    POINTS_NULLIFIER_ALREADY_USED: 'Proof: Points Nullifier Already Used',
    PROOF_RESULT_ACKNOWLEDGED: 'Proof: Proof Result Acknowledged',
    PROOF_VERIFY_CONFIRMATION_ACCEPTED: 'Proof: Verify Confirmation Accepted',
    PROOF_VERIFY_LONG_PRESS: 'Proof: Verify Button Long Pressed',
    PROVING_INIT: 'Proof: Proving Machine Init',
    PROVING_PROCESS_ERROR: 'Proof: Proving Process Error',
    PROVING_PROCESS_STARTED: 'Proof: Proving Process Started',
    PROVING_STATE_CHANGE: 'Proof: Proving State Change',
    QR_SCAN_CANCELLED: 'Proof: QR Scan Cancelled',
    QR_SCAN_FAILED: 'Proof: QR Scan Failed',
    QR_SCAN_REQUESTED: 'Proof: QR Scan Requested',
    QR_SCAN_SUCCESS: 'Proof: QR Scan Success',
    REGISTER_COMPLETED: 'Proof: Register Completed',
    SHARED_KEY_DERIVED: 'Proof: Shared Key Derived',
    SOCKETIO_CONNECT_ERROR: 'Proof: Socket.IO Connect Error',
    SOCKETIO_CONN_STARTED: 'Proof: Socket.IO Connection Started',
    SOCKETIO_DISCONNECT_UNEXPECTED:
      'Proof: Socket.IO Disconnected Unexpectedly',
    SOCKETIO_PROOF_FAILURE: 'Proof: Socket.IO Proof Failure',
    SOCKETIO_PROOF_SUCCESS: 'Proof: Socket.IO Proof Success',
    SOCKETIO_STATUS_RECEIVED: 'Proof: Socket.IO Status Received',
    SOCKETIO_SUBSCRIBED: 'Proof: Socket.IO Subscribed',
    TEE_CONN_FAILED: 'Proof: TEE Connection Failed',
    TEE_CONN_STARTED: 'Proof: TEE Connection Started',
    TEE_CONN_SUCCESS: 'Proof: TEE Connection Succeeded',
    TEE_WS_CLOSED: 'Proof: TEE WS Closed',
    TEE_WS_ERROR: 'Proof: TEE WS Error',
    USER_CONFIRMED: 'Proof: User Confirmed',
    VALIDATION_FAILED: 'Proof: Validation Failed',
    VALIDATION_STARTED: 'Proof: Validation Started',
    VALIDATION_SUCCESS: 'Proof: Validation Succeeded',
    WS_HELLO_ACK: 'Proof: WS Hello Acknowledged',
    WS_HELLO_SENT: 'Proof: WS Hello Sent',
  },
  ProofRequestPickerEvents: {
    VIEWED: 'proof_request_picker_viewed',
    ID_SELECTED: 'proof_request_id_selected',
    INELIGIBLE_ID_TAPPED: 'proof_request_ineligible_id_tapped',
  },
  SettingsEvents: {
    CONNECTION_MODAL_CLOSED: 'Settings: Connection Modal Closed',
    CONNECTION_MODAL_OPENED: 'Settings: Connection Modal Opened',
    CONNECTION_SETTINGS_OPENED: 'Settings: Connection Settings Opened',
  },
  WebViewEvents: {
    LOAD_FAILED: 'WebView: Load Failed',
    VERSION_MISMATCH: 'WebView: Version Mismatch',
    LOAD_RECOVERED: 'WebView: Load Recovered',
  },
}));

// Note: @selfxyz/mobile-sdk-alpha is NOT mocked to allow testing real package methods
// This is intentional for the mobile-sdk-alpha migration testing

// Mock react-native-keychain
jest.mock('react-native-keychain', () => ({
  SECURITY_LEVEL_ANY: 'MOCK_SECURITY_LEVEL_ANY',
  SECURITY_LEVEL_SECURE_SOFTWARE: 'MOCK_SECURITY_LEVEL_SECURE_SOFTWARE',
  SECURITY_LEVEL_SECURE_HARDWARE: 'MOCK_SECURITY_LEVEL_SECURE_HARDWARE',
  setGenericPassword: jest.fn(),
  getGenericPassword: jest.fn(),
  resetGenericPassword: jest.fn(),
  ACCESSIBLE: {
    WHEN_UNLOCKED: 'AccessibleWhenUnlocked',
    AFTER_FIRST_UNLOCK: 'AccessibleAfterFirstUnlock',
    ALWAYS: 'AccessibleAlways',
    WHEN_PASSCODE_SET_THIS_DEVICE_ONLY:
      'AccessibleWhenPasscodeSetThisDeviceOnly',
    WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'AccessibleWhenUnlockedThisDeviceOnly',
    AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY:
      'AccessibleAfterFirstUnlockThisDeviceOnly',
    ALWAYS_THIS_DEVICE_ONLY: 'AccessibleAlwaysThisDeviceOnly',
  },
  ACCESS_CONTROL: {
    USER_PRESENCE: 'UserPresence',
    BIOMETRY_ANY: 'BiometryAny',
    BIOMETRY_CURRENT_SET: 'BiometryCurrentSet',
    DEVICE_PASSCODE: 'DevicePasscode',
    APPLICATION_PASSWORD: 'ApplicationPassword',
    BIOMETRY_ANY_OR_DEVICE_PASSCODE: 'BiometryAnyOrDevicePasscode',
    BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE:
      'BiometryCurrentSetOrDevicePasscode',
  },
}));

// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () => ({
  setItem: jest.fn(),
  getItem: jest.fn(),
  removeItem: jest.fn(),
  mergeItem: jest.fn(),
  clear: jest.fn(),
  getAllKeys: jest.fn(),
  flushGetRequests: jest.fn(),
  multiGet: jest.fn(),
  multiSet: jest.fn(),
  multiRemove: jest.fn(),
  multiMerge: jest.fn(),
}));

// Mock react-native-check-version
jest.mock('react-native-check-version', () => ({
  checkVersion: jest.fn().mockResolvedValue({
    needsUpdate: false,
    currentVersion: '1.0.0',
    latestVersion: '1.0.0',
  }),
}));

// Mock @react-native-community/netinfo
jest.mock('@react-native-community/netinfo', () => {
  const addEventListener = jest.fn(() => jest.fn());
  const configure = jest.fn();
  const useNetInfo = jest.fn().mockReturnValue({
    type: 'wifi',
    isConnected: true,
    isInternetReachable: true,
    details: {
      isConnectionExpensive: false,
      cellularGeneration: '4g',
    },
  });
  const fetch = jest
    .fn()
    .mockResolvedValue({ isConnected: true, isInternetReachable: true });

  return {
    __esModule: true,
    addEventListener,
    configure,
    useNetInfo,
    fetch,
    default: {
      addEventListener,
      configure,
      fetch,
    },
  };
});

// Mock react-native-nfc-manager
jest.mock('react-native-nfc-manager', () => ({
  start: jest.fn(),
  isSupported: jest.fn().mockResolvedValue(true),
  isEnabled: jest.fn().mockResolvedValue(true),
  registerTagEvent: jest.fn(),
  unregisterTagEvent: jest.fn(),
  requestTechnology: jest.fn(),
  cancelTechnologyRequest: jest.fn(),
  getTag: jest.fn(),
  setAlertMessage: jest.fn(),
  sendMifareCommand: jest.fn(),
  sendCommandAPDU: jest.fn(),
  transceive: jest.fn(),
  getMaxTransceiveLength: jest.fn(),
  setTimeout: jest.fn(),
  connect: jest.fn(),
  close: jest.fn(),
  cleanUpTag: jest.fn(),
  default: {
    start: jest.fn(),
    isSupported: jest.fn().mockResolvedValue(true),
    isEnabled: jest.fn().mockResolvedValue(true),
    registerTagEvent: jest.fn(),
    unregisterTagEvent: jest.fn(),
    requestTechnology: jest.fn(),
    cancelTechnologyRequest: jest.fn(),
    getTag: jest.fn(),
    setAlertMessage: jest.fn(),
    sendMifareCommand: jest.fn(),
    sendCommandAPDU: jest.fn(),
    transceive: jest.fn(),
    getMaxTransceiveLength: jest.fn(),
    setTimeout: jest.fn(),
    connect: jest.fn(),
    close: jest.fn(),
    cleanUpTag: jest.fn(),
  },
}));

// Mock react-native-passport-reader
jest.mock('react-native-passport-reader', () => {
  const mockScanPassport = jest.fn();
  // Mock the parameter count for scanPassport (iOS native method takes 10 parameters)
  Object.defineProperty(mockScanPassport, 'length', { value: 10 });

  const mockPassportReader = {
    configure: jest.fn(),
    scanPassport: mockScanPassport,
    readPassport: jest.fn(),
    cancelPassportRead: jest.fn(),
    trackEvent: jest.fn(),
    flush: jest.fn(),
    reset: jest.fn(),
  };

  return {
    PassportReader: mockPassportReader,
    default: mockPassportReader,
    reset: jest.fn(),
    scan: jest.fn(),
  };
});

// NativeModules is already defined at the top of the file and assigned to global.NativeModules
// No need to redefine it here

// Mock @/integrations/nfc/passportReader to properly expose the interface expected by tests
jest.mock('./src/integrations/nfc/passportReader', () => {
  const mockScanPassport = jest.fn();
  // Mock the parameter count for scanPassport (iOS native method takes 10 parameters)
  Object.defineProperty(mockScanPassport, 'length', { value: 10 });

  const mockPassportReader = {
    configure: jest.fn(),
    scanPassport: mockScanPassport,
    trackEvent: jest.fn(),
    flush: jest.fn(),
  };

  return {
    PassportReader: mockPassportReader,
    reset: jest.fn(),
    scan: jest.fn(),
    isFixtureCaptureSupported: false,
    fixtureCapture: {
      isSupported: false,
      setEnabled: jest.fn().mockResolvedValue(false),
      listTapes: jest.fn().mockResolvedValue([]),
      readTape: jest.fn().mockResolvedValue(null),
      deleteTapes: jest.fn().mockResolvedValue(undefined),
    },
    isNfcDebugBridgeSupported: false,
    nfcDebugBridge: {
      isSupported: false,
      start: jest.fn().mockResolvedValue(false),
      stop: jest.fn().mockResolvedValue(false),
    },
    default: mockPassportReader,
  };
});

// Mock @stablelib packages
jest.mock('@stablelib/cbor', () => ({
  encode: jest.fn(),
  decode: jest.fn(),
}));

jest.mock('@stablelib/utf8', () => ({
  encode: jest.fn(),
  decode: jest.fn(),
}));

// Mock react-native-app-auth
jest.mock('react-native-app-auth', () => ({
  authorize: jest.fn().mockResolvedValue({ accessToken: 'mock-access-token' }),
}));

// Mock @robinbobin/react-native-google-drive-api-wrapper
jest.mock('@robinbobin/react-native-google-drive-api-wrapper', () => {
  class MockUploader {
    constructor() {
      this.execute = jest.fn();
    }
    setData() {
      return this;
    }
    setDataMimeType() {
      return this;
    }
    setRequestBody() {
      return this;
    }
  }

  class MockFiles {
    constructor() {
      this.list = jest.fn().mockResolvedValue({ files: [] });
      this.delete = jest.fn();
      this.getText = jest.fn().mockResolvedValue('');
    }
    newMultipartUploader() {
      return new MockUploader();
    }
  }

  class GDrive {
    constructor() {
      this.accessToken = '';
      this.files = new MockFiles();
    }
  }

  return {
    __esModule: true,
    GDrive,
    MIME_TYPES: { application: { json: 'application/json' } },
    APP_DATA_FOLDER_ID: 'appDataFolder',
  };
});

// Mock react-native-cloud-storage
jest.mock('react-native-cloud-storage', () => {
  const mockCloudStorage = {
    setProviderOptions: jest.fn(),
    isCloudAvailable: jest.fn().mockResolvedValue(true),
    createFolder: jest.fn(),
    deleteFolder: jest.fn(),
    listFiles: jest.fn(),
    readFile: jest.fn(),
    writeFile: jest.fn(),
    deleteFile: jest.fn(),
    getFileInfo: jest.fn(),
    getStorageInfo: jest.fn(),
    getProvider: jest.fn(),
    mkdir: jest.fn(),
    exists: jest.fn(),
    rmdir: jest.fn(),
  };

  return {
    __esModule: true,
    CloudStorage: mockCloudStorage,
    CloudStorageScope: {
      AppData: 'AppData',
      Documents: 'Documents',
      Full: 'Full',
    },
    CloudStorageProvider: {
      GoogleDrive: 'GoogleDrive',
      ICloud: 'ICloud',
    },
  };
});

// Mock @react-native-clipboard/clipboard
jest.mock('@react-native-clipboard/clipboard', () => ({
  getString: jest.fn().mockResolvedValue(''),
  setString: jest.fn(),
  hasString: jest.fn().mockResolvedValue(false),
}));

// Mock react-native-linear-gradient
jest.mock('react-native-linear-gradient', () => 'LinearGradient');

// Mock react-native-localize
jest.mock('react-native-localize', () => ({
  getLocales: jest.fn().mockReturnValue([
    {
      countryCode: 'US',
      languageTag: 'en-US',
      languageCode: 'en',
      isRTL: false,
    },
  ]),
  getCountry: jest.fn().mockReturnValue('US'),
  getTimeZone: jest.fn().mockReturnValue('America/New_York'),
  getCurrencies: jest.fn().mockReturnValue(['USD']),
  getTemperatureUnit: jest.fn().mockReturnValue('celsius'),
  getFirstWeekDay: jest.fn().mockReturnValue(0),
  uses24HourClock: jest.fn().mockReturnValue(false),
  usesMetricSystem: jest.fn().mockReturnValue(false),
  findBestAvailableLanguage: jest.fn().mockReturnValue({
    languageTag: 'en-US',
    isRTL: false,
  }),
  default: {
    getLocales: jest.fn().mockReturnValue([
      {
        countryCode: 'US',
        languageTag: 'en-US',
        languageCode: 'en',
        isRTL: false,
      },
    ]),
    getCountry: jest.fn().mockReturnValue('US'),
    getTimeZone: jest.fn().mockReturnValue('America/New_York'),
    getCurrencies: jest.fn().mockReturnValue(['USD']),
    getTemperatureUnit: jest.fn().mockReturnValue('celsius'),
    getFirstWeekDay: jest.fn().mockReturnValue(0),
    uses24HourClock: jest.fn().mockReturnValue(false),
    usesMetricSystem: jest.fn().mockReturnValue(false),
    findBestAvailableLanguage: jest.fn().mockReturnValue({
      languageTag: 'en-US',
      isRTL: false,
    }),
  },
}));

jest.mock('./src/services/notifications/notificationService', () =>
  require('./tests/__setup__/notificationServiceMock.js'),
);

// Mock react-native-svg
jest.mock('react-native-svg', () => {
  // Avoid requiring React to prevent nested require memory issues

  // Mock SvgXml component that handles XML strings
  const SvgXml = jest.fn(() => null);
  SvgXml.displayName = 'SvgXml';

  return {
    __esModule: true,
    default: SvgXml,
    SvgXml,
    Svg: jest.fn(() => null),
    Circle: jest.fn(() => null),
    Path: jest.fn(() => null),
    G: jest.fn(() => null),
    Rect: jest.fn(() => null),
    Defs: jest.fn(() => null),
    LinearGradient: jest.fn(() => null),
    Stop: jest.fn(() => null),
    ClipPath: jest.fn(() => null),
    Polygon: jest.fn(() => null),
    Polyline: jest.fn(() => null),
    Line: jest.fn(() => null),
    Text: jest.fn(() => null),
    TSpan: jest.fn(() => null),
  };
});

jest.mock('lottie-react-native', () => {
  const MockLottieView = jest.fn(() => null);
  MockLottieView.displayName = 'MockLottieView';

  return {
    __esModule: true,
    default: MockLottieView,
  };
});

// Mock React Navigation

// Mock react-native-biometrics to prevent NativeModules errors
jest.mock('react-native-biometrics', () => {
  class MockReactNativeBiometrics {
    constructor(options) {
      // Constructor accepts options but doesn't need to do anything
      this.isSensorAvailable = jest.fn().mockResolvedValue({
        available: true,
        biometryType: 'TouchID',
      });
      this.createKeys = jest
        .fn()
        .mockResolvedValue({ publicKey: 'mock-public-key' });
      this.deleteKeys = jest.fn().mockResolvedValue(true);
      this.createSignature = jest
        .fn()
        .mockResolvedValue({ signature: 'mock-signature' });
      this.simplePrompt = jest.fn().mockResolvedValue({ success: true });
    }
  }
  return {
    __esModule: true,
    default: MockReactNativeBiometrics,
  };
});

// Mock NativeAppState native module to prevent getCurrentAppState errors
jest.mock('react-native/Libraries/AppState/NativeAppState', () => ({
  __esModule: true,
  default: {
    getConstants: jest.fn(() => ({ initialAppState: 'active' })),
    getCurrentAppState: jest.fn(() => Promise.resolve({ app_state: 'active' })),
    addListener: jest.fn(),
    removeListeners: jest.fn(),
  },
}));

// Mock AppState to prevent getCurrentAppState errors
jest.mock('react-native/Libraries/AppState/AppState', () => {
  // Use the global appStateListeners array so tests can access it
  const appStateListeners = global.mockAppStateListeners || [];
  return {
    __esModule: true,
    default: {
      currentState: 'active',
      addEventListener: jest.fn((eventType, handler) => {
        appStateListeners.push(handler);
        return {
          remove: () => {
            const index = appStateListeners.indexOf(handler);
            if (index >= 0) {
              appStateListeners.splice(index, 1);
            }
          },
        };
      }),
    },
  };
});

// Mock react-native-permissions — use the library's bundled mock so every test
// can import it transitively without hitting the native module.
jest.mock('react-native-permissions', () =>
  require('react-native-permissions/mock'),
);

// Mock @didit-protocol/sdk-react-native
jest.mock('@didit-protocol/sdk-react-native', () => ({
  __esModule: true,
  startVerification: jest.fn().mockResolvedValue({
    type: 'completed',
    session: { status: 'approved', sessionId: 'mock-session-id' },
  }),
  startVerificationWithWorkflow: jest.fn().mockResolvedValue({
    type: 'completed',
    session: { status: 'approved', sessionId: 'mock-session-id' },
  }),
}));
