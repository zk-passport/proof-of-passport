// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  bridgeAnalyticsAdapter,
  bridgeAuthAdapter,
  bridgeBiometricsAdapter,
  bridgeCameraAdapter,
  bridgeCryptoAdapter,
  bridgeDocumentsAdapter,
  bridgeHapticAdapter,
  bridgeLifecycleAdapter,
  bridgeNFCScannerAdapter,
  bridgeStorageAdapter,
  noOpHapticAdapter,
  onNfcProgress,
  webNavigationAdapter,
} from '../adapters';
import { WebViewBridge } from '../bridge';
import { MockNativeBridge } from '../mock';
import { createMockWindow } from './helpers/mockWindow';

const engineBrowserMocks = vi.hoisted(() => ({
  createIndexedDBDocumentsAdapter: vi.fn(),
  createNoOpHapticAdapter: vi.fn(),
  createWebAnalyticsAdapter: vi.fn(),
  createWebCryptoAdapter: vi.fn(),
}));

vi.mock('@selfxyz/mobile-sdk-alpha/browser', () => engineBrowserMocks);

describe('Adapter integration tests', () => {
  let mock: MockNativeBridge;
  let bridge: WebViewBridge;
  let hashSpy: ReturnType<typeof vi.fn>;
  let noOpTriggerSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    hashSpy = vi.fn();
    noOpTriggerSpy = vi.fn();

    engineBrowserMocks.createWebCryptoAdapter.mockReset();
    engineBrowserMocks.createWebCryptoAdapter.mockReturnValue({
      hash: hashSpy,
      sign: vi.fn(),
      generateKey: vi.fn(),
      getPublicKey: vi.fn(),
    });
    engineBrowserMocks.createNoOpHapticAdapter.mockReset();
    engineBrowserMocks.createNoOpHapticAdapter.mockReturnValue(noOpTriggerSpy);

    mock = new MockNativeBridge();
    bridge = new WebViewBridge({ transport: mock });
    mock.connect(bridge);
  });

  afterEach(() => {
    bridge.destroy();
    vi.unstubAllGlobals();
  });

  describe('NFC Scanner Adapter', () => {
    it('should send scan request with 120s timeout', async () => {
      mock.handleWith('nfc', 'scanPassport', { passportData: { mrz: 'test' } });

      const scanner = bridgeNFCScannerAdapter(bridge);
      const result = await scanner.scan({
        passportNumber: '123',
        dateOfBirth: '900101',
        dateOfExpiry: '300101',
        sessionId: 'sess-1',
      });

      expect(result).toEqual({ passportData: { mrz: 'test' } });
      expect(mock.messagesFor('nfc')).toHaveLength(1);
    });

    it('should cancel on abort signal', async () => {
      // Handler that resolves when cancelScan fires
      let resolveScan: (v: unknown) => void;
      mock.handle(
        'nfc',
        'scanPassport',
        () =>
          new Promise(resolve => {
            resolveScan = resolve;
          }),
      );
      mock.handle('nfc', 'cancelScan', () => {
        // When cancel fires, resolve the scan with an error-like response
        // so the pending promise settles
        resolveScan!({ cancelled: true });
        return {};
      });

      const controller = new AbortController();
      const scanner = bridgeNFCScannerAdapter(bridge);

      const promise = scanner.scan({
        passportNumber: '123',
        dateOfBirth: '900101',
        dateOfExpiry: '300101',
        sessionId: 'sess-1',
        signal: controller.signal,
      });

      controller.abort();

      // The cancel message should be fired
      const cancelMessages = mock.messagesFor('nfc').filter(m => m.method === 'cancelScan');
      expect(cancelMessages).toHaveLength(1);

      // The scan request was resolved, so promise should settle
      const result = await promise;
      expect(result).toEqual({ cancelled: true });
    });

    it('should subscribe to scan progress events', () => {
      const handler = vi.fn();
      const unsub = onNfcProgress(bridge, handler);

      mock.pushEvent('nfc', 'scanProgress', {
        step: 'reading_dg2',
        percent: 60,
      });
      expect(handler).toHaveBeenCalledWith({
        step: 'reading_dg2',
        percent: 60,
      });

      unsub();
    });
  });

  describe('Crypto Adapter', () => {
    it('should hash using Web Crypto API (no bridge call)', async () => {
      const adapter = bridgeCryptoAdapter(bridge);
      const input = new TextEncoder().encode('hello');
      const expectedHash = new Uint8Array(32);
      hashSpy.mockResolvedValue(expectedHash);

      const hash = await adapter.hash(input, 'sha256');

      expect(hash).toBe(expectedHash);
      expect(hashSpy).toHaveBeenCalledWith(input, 'sha256');
      expect(mock.messages).toHaveLength(0); // No bridge calls
    });

    it('should normalize supported SHA-256 aliases through the shared browser adapter', async () => {
      const adapter = bridgeCryptoAdapter(bridge);
      const input = new TextEncoder().encode('hello');
      const normalizedHash = new Uint8Array(32);
      hashSpy.mockResolvedValue(normalizedHash);

      const normalized = await adapter.hash(input, 'sha256');
      const hyphenated = await adapter.hash(input, 'sha-256' as any);
      const uppercase = await adapter.hash(input, 'SHA256' as any);

      expect(hyphenated).toEqual(normalized);
      expect(uppercase).toEqual(normalized);
      expect(hashSpy).toHaveBeenNthCalledWith(1, input, 'sha256');
      expect(hashSpy).toHaveBeenNthCalledWith(2, input, 'sha-256');
      expect(hashSpy).toHaveBeenNthCalledWith(3, input, 'SHA256');
      expect(mock.messages).toHaveLength(0);
    });

    it('should sign via bridge', async () => {
      const mockSignature = btoa(String.fromCharCode(...new Uint8Array([1, 2, 3, 4])));
      mock.handleWith('crypto', 'sign', { signature: mockSignature });

      const adapter = bridgeCryptoAdapter(bridge);
      const result = await adapter.sign(new Uint8Array([10, 20]), 'key-ref');

      expect(result).toEqual(new Uint8Array([1, 2, 3, 4]));
      expect(mock.messagesFor('crypto')).toHaveLength(1);
    });

    it('should generate key via bridge', async () => {
      mock.handleWith('crypto', 'generateKey', {
        keyRef: 'my-key',
        success: true,
      });

      const adapter = bridgeCryptoAdapter(bridge);
      const result = await adapter.generateKey('my-key');

      expect(result).toEqual({ keyRef: 'my-key' });
      const messages = mock.messagesFor('crypto');
      expect(messages).toHaveLength(1);
      expect(messages[0].method).toBe('generateKey');
      expect(messages[0].params).toEqual({ keyRef: 'my-key' });
    });

    it('should reject key generation when native reports failure', async () => {
      mock.handleWith('crypto', 'generateKey', {
        keyRef: 'my-key',
        success: false,
      });

      const adapter = bridgeCryptoAdapter(bridge);

      await expect(adapter.generateKey('my-key')).rejects.toThrow('Native key generation failed');
    });

    it('should get public key via bridge and decode base64', async () => {
      const pubKeyBytes = new Uint8Array([4, 10, 20, 30, 40]);
      const pubKeyBase64 = btoa(String.fromCharCode(...pubKeyBytes));
      mock.handleWith('crypto', 'getPublicKey', {
        publicKey: pubKeyBase64,
      });

      const adapter = bridgeCryptoAdapter(bridge);
      const result = await adapter.getPublicKey('my-key');

      expect(result).toEqual(pubKeyBytes);
      const messages = mock.messagesFor('crypto');
      expect(messages).toHaveLength(1);
      expect(messages[0].method).toBe('getPublicKey');
      expect(messages[0].params).toEqual({ keyRef: 'my-key' });
    });
  });

  describe('Auth Adapter', () => {
    it('should return private key on success', async () => {
      mock.handleWith('secureStorage', 'get', { value: '0xdeadbeef' });

      const auth = bridgeAuthAdapter(bridge);
      const key = await auth.getPrivateKey();
      expect(key).toBe('0xdeadbeef');
    });

    it('should return null on error', async () => {
      mock.handleWithError('secureStorage', 'get', {
        code: 'BIOMETRIC_FAILED',
        message: 'User cancelled biometric',
      });

      const auth = bridgeAuthAdapter(bridge);
      const key = await auth.getPrivateKey();
      expect(key).toBeNull();
    });
  });

  describe('Documents Adapter', () => {
    it('should load document catalog', async () => {
      const catalog = { documents: [{ id: '1', name: 'Passport' }] };
      mock.handleWith('documents', 'loadCatalog', catalog);

      const docs = bridgeDocumentsAdapter(bridge);
      const result = await docs.loadDocumentCatalog();
      expect(result).toEqual(catalog);
    });

    it('should save document', async () => {
      mock.handleWith('documents', 'save', {});

      const docs = bridgeDocumentsAdapter(bridge);
      await docs.saveDocument('doc-1', { mrz: 'test' });

      const messages = mock.messagesFor('documents');
      expect(messages).toHaveLength(1);
      expect(messages[0].params).toEqual({
        id: 'doc-1',
        data: { mrz: 'test' },
      });
    });

    it('should delete document', async () => {
      mock.handleWith('documents', 'delete', {});

      const docs = bridgeDocumentsAdapter(bridge);
      await docs.deleteDocument('doc-1');

      expect(mock.messagesFor('documents')[0].method).toBe('delete');
    });
  });

  describe('Storage Adapter', () => {
    it('should get/set/remove values', async () => {
      mock.handleWith('secureStorage', 'get', { value: 'stored' });
      mock.handleWith('secureStorage', 'set', {});
      mock.handleWith('secureStorage', 'remove', {});

      const storage = bridgeStorageAdapter(bridge);

      await storage.set('key', 'value');
      const result = await storage.get('key');
      expect(result).toBe('stored');

      await storage.remove('key');
      expect(mock.messagesFor('secureStorage')).toHaveLength(3);
    });
  });

  describe('Analytics Adapter', () => {
    it('should fire events without awaiting', () => {
      const analytics = bridgeAnalyticsAdapter(bridge);

      analytics.trackEvent('page_view', { page: 'home' });
      analytics.trackNfcEvent('scan_started', { device: 'pixel' });
      analytics.logNFCEvent('info', 'Scan begun', { sessionId: 's1' });

      expect(mock.messagesFor('analytics')).toHaveLength(3);
      expect(bridge.pendingCount).toBe(0); // Fire-and-forget
    });
  });

  describe('Haptic Adapter', () => {
    it('should fire haptic without awaiting', () => {
      const haptic = bridgeHapticAdapter(bridge);
      haptic.trigger('impact');

      expect(mock.messagesFor('haptic')).toHaveLength(1);
      expect(bridge.pendingCount).toBe(0);
    });

    it('should expose a no-op wrapper without touching the bridge', () => {
      const haptic = noOpHapticAdapter();

      expect(() => haptic.trigger('impact')).not.toThrow();
      expect(noOpTriggerSpy).toHaveBeenCalledWith('impact');
      expect(mock.messagesFor('haptic')).toHaveLength(0);
    });
  });

  describe('Lifecycle Adapter', () => {
    it('should fire ready and dismiss', () => {
      const lifecycle = bridgeLifecycleAdapter(bridge);
      lifecycle.ready();
      lifecycle.dismiss();

      const messages = mock.messagesFor('lifecycle');
      expect(messages).toHaveLength(2);
      expect(messages[0].method).toBe('ready');
      expect(messages[1].method).toBe('dismiss');
      expect(bridge.pendingCount).toBe(0);
    });

    it('should await setResult', async () => {
      mock.handleWith('lifecycle', 'setResult', {});

      const lifecycle = bridgeLifecycleAdapter(bridge);
      await lifecycle.setResult({ success: true, verificationId: 'v-1' });

      expect(mock.messagesFor('lifecycle')[0].method).toBe('setResult');
    });

    it('should send browser-host results without creating a pending request', async () => {
      bridge.destroy();

      const hostTarget = {
        postMessage: vi.fn(),
      } as unknown as Window;

      vi.stubGlobal(
        'window',
        createMockWindow({
          parent: hostTarget,
        }),
      );

      bridge = new WebViewBridge({
        browserHost: {
          targetOrigin: 'https://host.example',
        },
      });

      const lifecycle = bridgeLifecycleAdapter(bridge);
      await lifecycle.setResult({ success: true, verificationId: 'v-1' });

      expect(bridge.pendingCount).toBe(0);
      expect(hostTarget.postMessage).toHaveBeenCalledWith(
        {
          type: 'self:result',
          version: 1,
          payload: {
            success: true,
            verificationId: 'v-1',
          },
        },
        'https://host.example',
      );
    });
  });

  describe('Navigation Adapter', () => {
    it('should map route names to paths', () => {
      const navigate = vi.fn();
      const goBack = vi.fn();
      const nav = webNavigationAdapter(navigate, goBack);

      nav.goTo('Home');
      expect(navigate).toHaveBeenCalledWith('/');

      nav.goTo('CountryPicker');
      expect(navigate).toHaveBeenCalledWith('/onboarding/country');

      nav.goBack();
      expect(goBack).toHaveBeenCalled();
    });

    it('should warn on unknown route', () => {
      const navigate = vi.fn();
      const goBack = vi.fn();
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const nav = webNavigationAdapter(navigate, goBack);

      nav.goTo('UnknownRoute' as any);
      expect(warn).toHaveBeenCalled();
      expect(navigate).not.toHaveBeenCalled();

      warn.mockRestore();
    });
  });

  describe('Biometrics Adapter', () => {
    it('should authenticate via bridge', async () => {
      // Native handler returns bare true on success
      mock.handleWith('biometrics', 'authenticate', true);

      const biometrics = bridgeBiometricsAdapter(bridge);
      const result = await biometrics.authenticate({ reason: 'Verify identity' });

      expect(result).toBe(true);
      expect(mock.messagesFor('biometrics')).toHaveLength(1);
      expect(mock.messagesFor('biometrics')[0].params).toEqual({
        reason: 'Verify identity',
      });
    });

    it('should reject when authentication fails', async () => {
      // Native handler throws BridgeHandlerException on failure
      mock.handleWithError('biometrics', 'authenticate', {
        code: 'BIOMETRIC_ERROR',
        message: 'User cancelled biometric',
      });

      const biometrics = bridgeBiometricsAdapter(bridge);
      await expect(biometrics.authenticate({ reason: 'Verify identity' })).rejects.toThrow('User cancelled biometric');
    });

    it('should check availability', async () => {
      // Native handler returns bare boolean
      mock.handleWith('biometrics', 'isAvailable', true);

      const biometrics = bridgeBiometricsAdapter(bridge);
      const result = await biometrics.isAvailable();

      expect(result).toBe(true);
    });

    it('should get biometry type', async () => {
      // Native handler returns bare string
      mock.handleWith('biometrics', 'getBiometryType', 'FaceID');

      const biometrics = bridgeBiometricsAdapter(bridge);
      const result = await biometrics.getBiometryType();

      expect(result).toBe('FaceID');
    });
  });

  describe('Camera Adapter', () => {
    it('should scan MRZ via bridge', async () => {
      // Native handler parses MRZ JSON into an object
      const mrzData = {
        documentNumber: 'AB1234567',
        dateOfBirth: '900101',
        dateOfExpiry: '300101',
      };
      mock.handleWith('camera', 'scanMRZ', mrzData);

      const camera = bridgeCameraAdapter(bridge);
      const result = await camera.scanMRZ();

      expect(result).toEqual(mrzData);
      expect(mock.messagesFor('camera')).toHaveLength(1);
    });

    it('should check camera availability', async () => {
      // Native handler returns bare boolean
      mock.handleWith('camera', 'isAvailable', true);

      const camera = bridgeCameraAdapter(bridge);
      const result = await camera.isAvailable();

      expect(result).toBe(true);
    });

    it('should stop the native camera when scanMRZ rejects', async () => {
      mock.handleWithError('camera', 'scanMRZ', { code: 'CAMERA_ERROR', message: 'boom' });

      const camera = bridgeCameraAdapter(bridge);
      await expect(camera.scanMRZ()).rejects.toThrow();

      const stopMessages = mock.messagesFor('camera').filter(m => m.method === 'stopCamera');
      expect(stopMessages).toHaveLength(1);
    });

    it('should time out scanMRZ after 120s and stop the native camera', async () => {
      vi.useFakeTimers();
      try {
        // Native never responds — the scan is orphaned.
        mock.handle('camera', 'scanMRZ', () => new Promise(() => {}));

        const camera = bridgeCameraAdapter(bridge);
        const promise = camera.scanMRZ();
        const rejection = expect(promise).rejects.toThrow(/timed out/);

        await vi.advanceTimersByTimeAsync(120_000);
        await rejection;

        const stopMessages = mock.messagesFor('camera').filter(m => m.method === 'stopCamera');
        expect(stopMessages).toHaveLength(1);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});
