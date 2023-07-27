import React, {useEffect, useState} from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  useColorScheme,
  View,
  Button,
  NativeModules,
  DeviceEventEmitter,
  TextInput,
  ActivityIndicator,
  Platform,
} from 'react-native';

import {
  Colors,
  DebugInstructions,
  Header,
  LearnMoreLinks,
  ReloadInstructions,
} from 'react-native/Libraries/NewAppScreen';
// @ts-ignore
import PassportReader from 'react-native-passport-reader';
import {checkInputs, getFirstName} from './utils/checks';
import {
  DEFAULT_PNUMBER,
  DEFAULT_DOB,
  DEFAULT_DOE,
  DEFAULT_ADDRESS,
  LOCAL_IP,
} from '@env';
import {PassportData} from './types/passportData';
import {dataHashesObjToArray} from './utils/utils';
import {Buffer} from 'buffer';

console.log('DEFAULT_PNUMBER', DEFAULT_PNUMBER);

const CACHE_DATA_IN_LOCAL_SERVER = true;
const SKIP_SCAN = false;

const hexToBytes = (hex: string) => {
  var bytes = [];

  for (var c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }

  return bytes;
};

function App(): JSX.Element {
  const isDarkMode = useColorScheme() === 'dark';
  const [passportNumber, setPassportNumber] = useState(DEFAULT_PNUMBER ?? '');
  const [dateOfBirth, setDateOfBirth] = useState(DEFAULT_DOB ?? '');
  const [dateOfExpiry, setDateOfExpiry] = useState(DEFAULT_DOE ?? '');
  const [address, setAddress] = useState(DEFAULT_ADDRESS ?? '');
  const [passportData, setPassportData] = useState<PassportData | null>(null);
  const [step, setStep] = useState('enterDetails');

  const backgroundStyle = {
    backgroundColor: isDarkMode ? Colors.darker : Colors.lighter,
  };

  useEffect(() => {
    const logEventListener = DeviceEventEmitter.addListener('LOG_EVENT', e => {
      console.log(e);
    });

    return () => {
      logEventListener.remove();
    };
  }, []);

  if (SKIP_SCAN && passportData === null) {
    console.log('skipping scan step...');
    fetch(`${LOCAL_IP}/passportData`)
      .then(response => response.json())
      .then(data => {
        console.log('passport data fetched');
        setPassportData(data);
        setStep('scanCompleted');
      });
  }

  async function handleResponse(response: any) {
    const {
      mrzInfo,
      publicKey,
      publicKeyPEM,
      dataGroupHashes,
      eContent,
      encryptedDigest,
      contentBytes,
      eContentDecomposed,
    } = response;

    const passportData = {
      mrzInfo: JSON.parse(mrzInfo),
      publicKey: publicKey,
      publicKeyPEM: publicKeyPEM,
      dataGroupHashes: dataHashesObjToArray(JSON.parse(dataGroupHashes)),
      eContent: JSON.parse(eContent),
      encryptedDigest: JSON.parse(encryptedDigest),
      contentBytes: JSON.parse(contentBytes),
      eContentDecomposed: JSON.parse(eContentDecomposed),
    };

    console.log('mrzInfo', passportData.mrzInfo);
    console.log('publicKey', passportData.publicKey);
    console.log('publicKeyPEM', passportData.publicKeyPEM);
    console.log('dataGroupHashes', passportData.dataGroupHashes);
    console.log('eContent', passportData.eContent);
    console.log('encryptedDigest', passportData.encryptedDigest);
    console.log('contentBytes', passportData.contentBytes);
    console.log('eContentDecomposed', passportData.eContentDecomposed);

    setPassportData(passportData);

    if (CACHE_DATA_IN_LOCAL_SERVER) {
      // Caches data in local server to avoid having to scan the passport each time
      // For development purposes only
      fetch(`${LOCAL_IP}/post`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(passportData),
      })
        .then(response => response.json())
        .then(data => console.log(data.message))
        .catch(error => {
          console.log('error caching data in local server', error);
        });
    }

    setStep('scanCompleted');
  }

  async function scanAndroid() {
    try {
      const response = await PassportReader.scan({
        documentNumber: passportNumber,
        dateOfBirth: dateOfBirth,
        dateOfExpiry: dateOfExpiry,
      });
      console.log('scanned');
      handleResponse(response);
    } catch (e) {
      console.log('error :', e);
    }
  }

  const handleProve = () => {
    if (passportData === null) {
      console.log('passport data is null');
      return;
    }

    // const mrz = computeMrz(passportData);

    // 1. Compute the eContent from the mrzInfo and the dataGroupHashes

    // 2. check that it matches the eContent from the passportData

    // 3. Check the signature in js

    // 4. Format all the data as inputs for the circuit

    // 5. Generate a proof of passport
  };

  const handleMint = () => {
    // 6. Format the proof and publicInputs as calldata for the verifier contract
    // 7. Call the verifier contract with the calldata
  };

  const scanIphone = async () => {
    const value = await NativeModules.PassportReader.scanPassport(
      passportNumber,
      dateOfBirth,
      dateOfExpiry,
    );
    console.log(`native tells us ${value[0]}`);
    // const buffer = Buffer.from(value[3], 'base64');
    // const bufString = buffer.toString('hex');
    // console.log(bufString);
    // console.log(hexToBytes(bufString));

    const passportData: PassportData = {
      mrzInfo: {
        compositeCheckDigit: '0',
        dateOfBirth: '000000',
        dateOfBirthCheckDigit: '0',
        dateOfExpiry: '000000',
        dateOfExpiryCheckDigit: '0',
        documentCode: '0',
        documentNumber: '0',
        documentNumberCheckDigit: '0',
        documentType: 0,
        gender: '0',
        issuingState: '0',
        nationality: '0',
        optionalData1: '0',
        primaryIdentifier: '0',
        secondaryIdentifier: '0',
      },
      publicKey: '',
      publicKeyPEM: '',
      dataGroupHashes: [[0, [0]]],
      eContent: '',
      encryptedDigest: '',
      contentBytes: '',
      eContentDecomposed: '',
    };

    setPassportData(passportData);
    setStep('scanCompleted');
  };

  const scan = () => {
    checkInputs(passportNumber, dateOfBirth, dateOfExpiry);

    // 1. start a scan
    // 2. press the back of your android phone against the passport
    // 3. wait for the scan(...) Promise to get resolved/rejected
    console.log('scanning...');
    setStep('scanning');

    if (Platform.OS === 'android') {
      scanAndroid();
    } else {
      scanIphone();
    }
  };

  return (
    <SafeAreaView style={backgroundStyle}>
      <StatusBar
        barStyle={isDarkMode ? 'light-content' : 'dark-content'}
        backgroundColor={backgroundStyle.backgroundColor}
      />
      <ScrollView
        contentInsetAdjustmentBehavior="automatic"
        style={backgroundStyle}>
        <View
          style={{
            backgroundColor: isDarkMode ? Colors.black : Colors.white,
          }}>
          {step === 'enterDetails' ? (
            <View style={styles.sectionContainer}>
              <Text style={styles.header}>Enter Your Passport Details</Text>
              <TextInput
                style={styles.input}
                onChangeText={setPassportNumber}
                value={passportNumber}
                placeholder="Passport Number"
              />
              <TextInput
                style={styles.input}
                onChangeText={setDateOfBirth}
                value={dateOfBirth}
                placeholder="Date of Birth (YYYY-MM-DD)"
              />
              <TextInput
                style={styles.input}
                onChangeText={setDateOfExpiry}
                value={dateOfExpiry}
                placeholder="Date of Expiry (YYYY-MM-DD)"
              />
              <Button title="Scan Passport with NFC" onPress={scan} />
            </View>
          ) : null}
          {step === 'scanning' ? (
            <View style={styles.sectionContainer}>
              <Text style={styles.header}>Put your phone on your passport</Text>
              <ActivityIndicator
                size="large"
                color="#00ff00"
                style={{marginTop: 20}}
              />
            </View>
          ) : null}
          {step === 'scanCompleted' ? (
            <View style={styles.sectionContainer}>
              <Text style={styles.header}>Connection successful</Text>
              <Text style={styles.header}>
                Hi {getFirstName(passportData?.mrzInfo)} !{' '}
              </Text>
              <Text style={styles.header}>Input your address or ens</Text>
              <TextInput
                style={styles.input}
                onChangeText={setAddress}
                value={address}
                placeholder="Your Address or ens name"
              />
              <Button title="Generate zk proof" onPress={handleProve} />
            </View>
          ) : null}
          {step === 'proofGenerated' ? (
            <View style={styles.sectionContainer}>
              <Text style={styles.header}>Zero-knowledge proof generated</Text>
              <Text style={styles.header}>You can now mint your SBT</Text>
              <Button title="Mint Proof of Passport" onPress={handleMint} />
            </View>
          ) : null}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  sectionContainer: {
    marginTop: 32,
    paddingHorizontal: 24,
  },
  sectionTitle: {
    fontSize: 24,
    fontWeight: '600',
  },
  sectionDescription: {
    marginTop: 8,
    fontSize: 18,
    fontWeight: '400',
  },
  highlight: {
    fontWeight: '700',
  },
  header: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginTop: 20,
  },
  input: {
    height: 40,
    margin: 12,
    borderWidth: 1,
    padding: 10,
  },
});

export default App;
