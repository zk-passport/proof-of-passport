// SPDX-FileCopyrightText: 2025-2026 Social Connect Labs, Inc.
// SPDX-License-Identifier: BUSL-1.1
// NOTE: Converts to Apache-2.0 on 2029-06-11 per LICENSE.

import React, { useState } from 'react';
import {
  Platform,
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
  getMrzScannerModule,
  isMrzScannerAvailable,
  type MrzScanResult,
} from '@selfxyz/rn-mrz-scanner';
import {
  getSelfPassportReader,
  isSelfPassportReaderAvailable,
} from '@selfxyz/rn-nfc-passport';

type ScanStatus =
  | { state: 'idle' }
  | { state: 'scanning' }
  | { state: 'done'; detail: string }
  | { state: 'error'; code: string; message: string };

function errorInfo(err: unknown): { code: string; message: string } {
  const e = err as { code?: string; message?: string };
  return {
    code: typeof e?.code === 'string' ? e.code : 'UNKNOWN',
    message: typeof e?.message === 'string' ? e.message : String(err),
  };
}

export function DirectCaptureScreen({
  onBack,
}: {
  onBack: () => void;
}): React.JSX.Element {
  const [documentNumber, setDocumentNumber] = useState('');
  const [dateOfBirth, setDateOfBirth] = useState('');
  const [dateOfExpiry, setDateOfExpiry] = useState('');
  const [mrzStatus, setMrzStatus] = useState<ScanStatus>({ state: 'idle' });
  const [nfcStatus, setNfcStatus] = useState<ScanStatus>({ state: 'idle' });

  const mrzAvailable = isMrzScannerAvailable();
  const nfcAvailable = isSelfPassportReaderAvailable();
  const bacKeysPresent =
    documentNumber.length > 0 &&
    dateOfBirth.length === 6 &&
    dateOfExpiry.length === 6;

  const scanMrz = async () => {
    const scanner = getMrzScannerModule();
    if (!scanner) {
      setMrzStatus({
        state: 'error',
        code: 'NOT_AVAILABLE',
        message: 'SelfMRZScannerModule is not linked in this build.',
      });
      return;
    }
    setMrzStatus({ state: 'scanning' });
    try {
      const result: MrzScanResult = await scanner.startScanning({});
      setDocumentNumber(result.documentNumber);
      setDateOfBirth(result.dateOfBirth);
      setDateOfExpiry(result.dateOfExpiry);
      setMrzStatus({
        state: 'done',
        detail: `type=${result.documentType ?? '?'} country=${result.countryCode ?? '?'}`,
      });
    } catch (err) {
      setMrzStatus({ state: 'error', ...errorInfo(err) });
    }
  };

  const readChip = async () => {
    const reader = getSelfPassportReader();
    if (!reader) {
      setNfcStatus({
        state: 'error',
        code: 'NOT_AVAILABLE',
        message: 'SelfPassportReader is not linked in this build.',
      });
      return;
    }
    setNfcStatus({ state: 'scanning' });
    try {
      // The native module's entry point differs per platform: iOS exposes the
      // 10-arg positional scanPassport, Android the options-object scan.
      let resultJson: string;
      if (Platform.OS === 'ios' && reader.scanPassport) {
        resultJson = await reader.scanPassport(
          documentNumber,
          dateOfBirth,
          dateOfExpiry,
          '',
          false,
          false,
          false,
          false,
          true,
          `direct-${Date.now()}`,
        );
      } else if (reader.scan) {
        resultJson = await reader.scan({
          documentNumber,
          dateOfBirth,
          dateOfExpiry,
        });
      } else {
        throw { code: 'NOT_AVAILABLE', message: 'No scan entry point found.' };
      }
      setNfcStatus({
        state: 'done',
        detail: `${resultJson.length} chars\n${resultJson.slice(0, 400)}${resultJson.length > 400 ? '…' : ''}`,
      });
    } catch (err) {
      setNfcStatus({ state: 'error', ...errorInfo(err) });
    }
  };

  const cancelChipRead = async () => {
    try {
      await getSelfPassportReader()?.cancelScan?.();
    } catch {
      // Cancel is best-effort; the scan promise rejects with its own error.
    }
  };

  const renderStatus = (status: ScanStatus) => {
    switch (status.state) {
      case 'idle':
        return <Text style={styles.detail}>Idle</Text>;
      case 'scanning':
        return <Text style={styles.detail}>Scanning…</Text>;
      case 'done':
        return <Text style={styles.payload}>{status.detail}</Text>;
      case 'error':
        return (
          <Text style={styles.errorText}>
            {status.code}: {status.message}
          </Text>
        );
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" />
      <View style={styles.topBar}>
        <TouchableOpacity onPress={onBack}>
          <Text style={styles.backLink}>‹ Back</Text>
        </TouchableOpacity>
        <Text style={styles.topBarTitle}>Direct Capture</Text>
      </View>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.description}>
          Calls the capture packages directly, without the WebView flow. Scan
          the MRZ to fill the BAC keys, then read the chip over NFC.
        </Text>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>
            1. MRZ Scan ({mrzAvailable ? 'available' : 'unavailable'})
          </Text>
          <TouchableOpacity
            style={styles.primaryButton}
            onPress={scanMrz}
            disabled={mrzStatus.state === 'scanning'}
          >
            <Text style={styles.primaryButtonText}>Scan MRZ</Text>
          </TouchableOpacity>
          {renderStatus(mrzStatus)}
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>
            2. NFC Chip Read ({nfcAvailable ? 'available' : 'unavailable'})
          </Text>

          <Text style={styles.label}>Document Number</Text>
          <TextInput
            style={styles.input}
            value={documentNumber}
            onChangeText={setDocumentNumber}
            placeholder="L898902C3"
            autoCapitalize="characters"
            autoCorrect={false}
          />
          <Text style={styles.label}>Date of Birth (YYMMDD)</Text>
          <TextInput
            style={styles.input}
            value={dateOfBirth}
            onChangeText={setDateOfBirth}
            placeholder="740812"
            keyboardType="number-pad"
            maxLength={6}
          />
          <Text style={styles.label}>Date of Expiry (YYMMDD)</Text>
          <TextInput
            style={styles.input}
            value={dateOfExpiry}
            onChangeText={setDateOfExpiry}
            placeholder="120415"
            keyboardType="number-pad"
            maxLength={6}
          />

          <TouchableOpacity
            style={[
              styles.primaryButton,
              !bacKeysPresent && styles.buttonDisabled,
            ]}
            onPress={readChip}
            disabled={!bacKeysPresent || nfcStatus.state === 'scanning'}
          >
            <Text style={styles.primaryButtonText}>Read Chip</Text>
          </TouchableOpacity>
          {nfcStatus.state === 'scanning' && (
            <TouchableOpacity
              style={styles.secondaryButton}
              onPress={cancelChipRead}
            >
              <Text style={styles.secondaryButtonText}>Cancel</Text>
            </TouchableOpacity>
          )}
          {renderStatus(nfcStatus)}
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
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingHorizontal: 16,
    paddingVertical: 14,
    backgroundColor: '#f6f7f8',
  },
  backLink: {
    fontSize: 16,
    color: '#0969da',
    fontWeight: '600',
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
  card: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 16,
    gap: 10,
  },
  cardTitle: {
    fontSize: 15,
    fontWeight: '600',
    color: '#1f2937',
  },
  label: {
    fontSize: 12,
    fontWeight: '500',
    color: '#6b7280',
    marginBottom: -6,
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
  buttonDisabled: {
    opacity: 0.4,
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
  detail: {
    fontSize: 13,
    color: '#374151',
  },
  errorText: {
    fontSize: 13,
    color: '#b91c1c',
  },
  payload: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: '#374151',
    lineHeight: 18,
  },
});
