// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import React, { useMemo, useState } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';

import {
  SelfVerification,
  type SelfSdkError,
  type VerificationResult,
} from '@selfxyz/rn-sdk';
// Optional capture packages. Installing them autolinks the native modules and
// makes the nfc / mrzCamera capabilities available; the exported helpers are
// safe to import even when unlinked (they never touch NativeModules at import).
import { isMrzScannerAvailable } from '@selfxyz/rn-mrz-scanner';
import { isSelfPassportReaderAvailable } from '@selfxyz/rn-nfc-passport';

import { DirectCaptureScreen } from './DirectCaptureScreen';

type CallbackState =
  | { status: 'Idle' }
  | { status: 'Launching verification...' }
  | { status: 'Success'; payload: string }
  | { status: 'Failure'; code: string; message: string }
  | { status: 'Cancelled' };

type LaunchFlow = 'onboarding' | 'disclose';

function App(): React.JSX.Element {
  const [isVerifying, setIsVerifying] = useState(false);
  const [flow, setFlow] = useState<LaunchFlow>('onboarding');
  const [showDirectCapture, setShowDirectCapture] = useState(false);
  const [userId, setUserId] = useState('example-user');
  const [scope, setScope] = useState('identity');
  const [callback, setCallback] = useState<CallbackState>({ status: 'Idle' });

  const captureCaps = useMemo(
    () => ({
      mrzCamera: isMrzScannerAvailable(),
      nfc: isSelfPassportReaderAvailable(),
    }),
    [],
  );

  // The WebView's InitialRouteRedirect sends any request carrying `disclosures`
  // (or `proofItems`) straight to the disclose flow. Omitting them lands on the
  // Self-app home, from which the passport MRZ + NFC onboarding starts.
  const request = useMemo(
    () => ({
      userId: userId || undefined,
      scope: scope || undefined,
      ...(flow === 'disclose'
        ? { disclosures: ['name', 'nationality', 'date_of_birth'] }
        : {}),
    }),
    [userId, scope, flow],
  );

  const launch = (nextFlow: LaunchFlow) => {
    setFlow(nextFlow);
    setCallback({ status: 'Launching verification...' });
    setIsVerifying(true);
  };

  const handleSuccess = (result: VerificationResult) => {
    setCallback({
      status: 'Success',
      payload: JSON.stringify(result, null, 2),
    });
    setIsVerifying(false);
  };

  const handleFailure = (error: SelfSdkError) => {
    setCallback({
      status: 'Failure',
      code: error.code,
      message: error.message,
    });
    setIsVerifying(false);
  };

  const handleCancelled = () => {
    setCallback({ status: 'Cancelled' });
    setIsVerifying(false);
  };

  if (showDirectCapture) {
    return <DirectCaptureScreen onBack={() => setShowDirectCapture(false)} />;
  }

  if (isVerifying) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar barStyle="dark-content" />
        <SelfVerification
          request={request}
          mode="self-app"
          onSuccess={handleSuccess}
          onFailure={handleFailure}
          onCancelled={handleCancelled}
          debug={__DEV__}
          style={styles.verificationView}
        />
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" />
      <View style={styles.topBar}>
        <Text style={styles.topBarTitle}>Self RN SDK Example</Text>
      </View>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.description}>
          Runs the full Self verification flow inside the bundled WebView:
          passport MRZ camera scan followed by an NFC chip read.
        </Text>

        <Text style={styles.label}>User ID</Text>
        <TextInput
          style={styles.input}
          value={userId}
          onChangeText={setUserId}
          placeholder="example-user"
          autoCapitalize="none"
          autoCorrect={false}
        />

        <Text style={styles.label}>Scope</Text>
        <TextInput
          style={styles.input}
          value={scope}
          onChangeText={setScope}
          placeholder="identity"
          autoCapitalize="none"
          autoCorrect={false}
        />

        <TouchableOpacity
          style={styles.primaryButton}
          onPress={() => launch('onboarding')}
        >
          <Text style={styles.primaryButtonText}>
            Start Self App Verification (MRZ + NFC)
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.primaryButton}
          onPress={() => launch('disclose')}
        >
          <Text style={styles.primaryButtonText}>
            Start Disclosure (prove name / nationality / DOB)
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.secondaryButton}
          onPress={() => setShowDirectCapture(true)}
        >
          <Text style={styles.secondaryButtonText}>
            Direct Capture Demo (standalone packages)
          </Text>
        </TouchableOpacity>

        <View style={styles.callbackCard}>
          <Text style={styles.callbackLabel}>Capture Modules</Text>
          <Text style={styles.callbackDetail}>
            mrzCamera: {captureCaps.mrzCamera ? 'available' : 'unavailable'}
          </Text>
          <Text style={styles.callbackDetail}>
            nfc: {captureCaps.nfc ? 'available' : 'unavailable'}
          </Text>
        </View>

        <View style={styles.callbackCard}>
          <Text style={styles.callbackLabel}>
            Callback Status: {callback.status}
          </Text>
          {callback.status === 'Failure' && (
            <>
              <Text style={styles.callbackDetail}>
                Error Code: {callback.code}
              </Text>
              <Text style={styles.callbackDetail}>
                Error Message: {callback.message}
              </Text>
            </>
          )}
          {callback.status === 'Success' && (
            <Text style={styles.callbackPayload}>{callback.payload}</Text>
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f6f7f8',
  },
  topBar: {
    paddingHorizontal: 16,
    paddingVertical: 14,
    backgroundColor: '#f6f7f8',
  },
  topBarTitle: {
    fontSize: 22,
    fontWeight: '700',
    color: '#111827',
  },
  content: {
    paddingHorizontal: 16,
    paddingBottom: 32,
    gap: 12,
  },
  description: {
    fontSize: 14,
    color: '#374151',
    lineHeight: 20,
  },
  label: {
    fontSize: 12,
    fontWeight: '500',
    color: '#6b7280',
    marginBottom: -8,
  },
  input: {
    borderWidth: 1,
    borderColor: '#d1d5db',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
    color: '#111827',
    backgroundColor: '#ffffff',
  },
  primaryButton: {
    backgroundColor: '#111827',
    borderRadius: 10,
    paddingVertical: 14,
    alignItems: 'center',
  },
  primaryButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '600',
  },
  secondaryButton: {
    backgroundColor: '#ffffff',
    borderColor: '#0969da',
    borderWidth: 1,
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: 'center',
  },
  secondaryButtonText: {
    color: '#0969da',
    fontSize: 15,
    fontWeight: '600',
  },
  callbackCard: {
    backgroundColor: '#e8e5f0',
    borderRadius: 12,
    padding: 16,
    gap: 6,
  },
  callbackLabel: {
    fontSize: 14,
    fontWeight: '500',
    color: '#1f2937',
  },
  callbackDetail: {
    fontSize: 13,
    color: '#374151',
  },
  callbackPayload: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: '#374151',
    lineHeight: 18,
  },
  verificationView: {
    flex: 1,
  },
});

export default App;
