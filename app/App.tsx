import React, {useEffect, useState} from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  useColorScheme,
  NativeModules,
  DeviceEventEmitter,
  TextInput,
  Platform,
} from 'react-native';

import {
  Colors,
  DebugInstructions,
  Header,
  LearnMoreLinks,
  ReloadInstructions,
} from 'react-native/Libraries/NewAppScreen';
import {
  Text,
  GluestackUIProvider,
  Checkbox,
  CheckboxIndicator,
  CheckboxIcon,
  CheckIcon,
  CheckboxLabel,
  Input,
  InputField,
  ButtonText,
  ButtonIcon,
  Button,
  Spinner,
  View,
  ButtonSpinner,
} from "@gluestack-ui/themed"
import { config } from "@gluestack-ui/config" // Optional if you want to use default theme
import Toast, { BaseToast, ErrorToast, SuccessToast, ToastProps } from 'react-native-toast-message';

// @ts-ignore
import PassportReader from 'react-native-passport-reader';
import {getFirstName, formatDuration, checkInputs } from './utils/utils';
import {
  DEFAULT_PNUMBER,
  DEFAULT_DOB,
  DEFAULT_DOE,
  DEFAULT_ADDRESS,
} from '@env';
import {DataHash, PassportData} from '../common/src/utils/types';
import {AWS_ENDPOINT} from '../common/src/constants/constants';
import {
  hash,
  toUnsignedByte,
  bytesToBigDecimal,
  dataHashesObjToArray,
  formatAndConcatenateDataHashes,
  formatMrz,
  splitToWords,
  hexStringToSignedIntArray,
  formatProofIOS,
  formatInputsIOS
} from '../common/src/utils/utils';
import { samplePassportData } from '../common/src/utils/passportDataStatic';

import "@ethersproject/shims"
import { ethers } from "ethers";
import axios from 'axios';
import groth16ExportSolidityCallData from './utils/snarkjs';
import contractAddresses from "./deployments/addresses.json"
import proofOfPassportArtefact from "./deployments/ProofOfPassport.json";
import forge from 'node-forge';
import { Buffer } from 'buffer';
global.Buffer = Buffer;

import CustomTextInput from './src/components/CustomTextInput';
import EnterDetailsScreen from './src/screens/EnterDetailsScreen';

console.log('DEFAULT_PNUMBER', DEFAULT_PNUMBER);

const SKIP_SCAN = false;

const attributeToPosition = {
  issuing_state: [2, 5],
  name: [5, 44],
  passport_number: [44, 52],
  nationality: [54, 57],
  date_of_birth: [57, 63],
  gender: [64, 65],
  expiry_date: [65, 71],
}

function App(): JSX.Element {
  const isDarkMode = useColorScheme() === 'dark';
  const [passportNumber, setPassportNumber] = useState(DEFAULT_PNUMBER ?? '');
  const [dateOfBirth, setDateOfBirth] = useState(DEFAULT_DOB ?? '');
  const [dateOfExpiry, setDateOfExpiry] = useState(DEFAULT_DOE ?? '');
  const [address, setAddress] = useState(DEFAULT_ADDRESS ?? '');
  const [passportData, setPassportData] = useState<PassportData | null>(null);
  const [step, setStep] = useState('enterDetails');
  const [testResult, setTestResult] = useState<any>(null);
  const [error, setError] = useState<any>(null);

  const [generatingProof, setGeneratingProof] = useState<boolean>(false);

  const [proofTime, setProofTime] = useState<number>(0);
  const [totalTime, setTotalTime] = useState<number>(0);
  const [proof, setProof] = useState<{proof: string, inputs: string} | null>(null);
  const [minting, setMinting] = useState<boolean>(false);
  const [mintText, setMintText] = useState<string | null>(null);

  const [disclosure, setDisclosure] = useState({
    issuing_state: false,
    name: false,
    passport_number: false,
    nationality: false,
    date_of_birth: false,
    gender: false,
    expiry_date: false,
  });

  const startCameraScan = () => {
    if (Platform.OS !== 'android') {
      Toast.show({
        type: 'info',
        text1: "Camera scan supported soon on iOS",
      })
      return
    }
    NativeModules.CameraActivityModule.startCameraActivity()
      .then((mrzInfo: string) => {
        const lines = mrzInfo.split('\n');
          if (lines.length >= 2) {
            const secondLine = lines[1];
            const passportNumber = secondLine.substring(0, 9).replace(/</g, '').trim(); 
            const dateOfBirth = secondLine.substring(13, 19); 
            const dateOfExpiry = secondLine.substring(21, 27); 
            setPassportNumber(passportNumber);
            setDateOfBirth(dateOfBirth);
            setDateOfExpiry(dateOfExpiry);
      } else {
        console.error('Invalid MRZ format');
      }
      })
      .catch((error: any) => {
        console.error('Camera Activity Error:', error);
      });
  };

  
  const handleDisclosureChange = (field: keyof typeof disclosure) => {
    setDisclosure(
      {...disclosure,
        [field]: !disclosure[field]
      });
  };

  const backgroundStyle = {
    backgroundColor:  Colors.white,
    flex:1
  };

  const inputStyle = StyleSheet.create({
    inputField: {
      minHeight: 45, // Set a minimum height that fits the text
      // Add other styles as needed to match your design
    },
    // Include any other styles you want to apply to the input component
  });

  useEffect(() => {
    const logEventListener = DeviceEventEmitter.addListener('LOG_EVENT', e => {
      console.log(e);
    });

    return () => {
      logEventListener.remove();
    };
  }, []);

  useEffect(() => {
    if (Platform.OS !== 'android') {
      NativeModules.Prover.runInitAction() // for mopro, ios only rn
    }
    if (SKIP_SCAN && passportData === null) {
      setPassportData(samplePassportData as PassportData);
      setStep('scanCompleted');
    }
  }, []);

  async function handleResponseIOS(response: any) {
    const parsed = JSON.parse(response);

    const eContentBase64 = parsed.eContentBase64; // this is what we call concatenatedDataHashes in our world
    const signedAttributes = parsed.signedAttributes; // this is what we call eContent in our world
    const signatureAlgorithm = parsed.signatureAlgorithm;
    const mrz = parsed.passportMRZ;
    const dataGroupHashes = parsed.dataGroupHashes;
    const signatureBase64 = parsed.signatureBase64;
    
    console.log('parsed.documentSigningCertificate', parsed.documentSigningCertificate)
    const pem = JSON.parse(parsed.documentSigningCertificate).PEM.replace(/\\\\n/g, '\n')
    console.log('pem', pem)
    
    const cert = forge.pki.certificateFromPem(pem);
    const publicKey = cert.publicKey;
    console.log('publicKey', publicKey)
    
    const modulus = (publicKey as any).n.toString(10);

    const eContentArray = Array.from(Buffer.from(signedAttributes, 'base64'));
    const signedEContentArray = eContentArray.map(byte => byte > 127 ? byte - 256 : byte);

    const concatenatedDataHashesArray = Array.from(Buffer.from(eContentBase64, 'base64'));
    const concatenatedDataHashesArraySigned = concatenatedDataHashesArray.map(byte => byte > 127 ? byte - 256 : byte);
    
    const dgHashes = JSON.parse(dataGroupHashes);
    console.log('dgHashes', dgHashes)
    
    const dataGroupHashesArray = Object.keys(dgHashes)
      .map(key => {
        const dgNumber = parseInt(key.replace('DG', ''));
        const hashArray = hexStringToSignedIntArray(dgHashes[key].computedHash);
        return [dgNumber, hashArray];
      })
      .sort((a, b) => (a[0] as number) - (b[0] as number));
    
    const encryptedDigestArray = Array.from(Buffer.from(signatureBase64, 'base64')).map(byte => byte > 127 ? byte - 256 : byte);
    
    const passportData = {
      mrz,
      signatureAlgorithm,
      pubKey: {
        modulus: modulus,
      },
      dataGroupHashes: concatenatedDataHashesArraySigned,
      eContent: signedEContentArray,
      encryptedDigest: encryptedDigestArray,
    };
    
    console.log('mrz', passportData.mrz);
    console.log('signatureAlgorithm', passportData.signatureAlgorithm);
    console.log('pubKey', passportData.pubKey);
    console.log('dataGroupHashes', passportData.dataGroupHashes);
    console.log('eContent', passportData.eContent);
    console.log('encryptedDigest', passportData.encryptedDigest);

    setPassportData(passportData);
    setStep('scanCompleted');
  }

  async function handleResponseAndroid(response: any) {
    const {
      mrz,
      signatureAlgorithm,
      modulus,
      curveName,
      publicKeyQ,
      dataGroupHashes,
      eContent,
      encryptedDigest,
    } = response;

    const passportData: PassportData = {
      mrz: mrz.replace(/\n/g, ''),
      signatureAlgorithm: signatureAlgorithm,
      pubKey: {
        modulus: modulus,
        curveName: curveName,
        publicKeyQ: publicKeyQ,
      },
      dataGroupHashes: dataHashesObjToArray(JSON.parse(dataGroupHashes)),
      eContent: JSON.parse(eContent),
      encryptedDigest: JSON.parse(encryptedDigest),
    };

    console.log('mrz', passportData.mrz);
    console.log('signatureAlgorithm', passportData.signatureAlgorithm);
    console.log('pubKey', passportData.pubKey);
    console.log('dataGroupHashes', passportData.dataGroupHashes);
    console.log('eContent', passportData.eContent);
    console.log('encryptedDigest', passportData.encryptedDigest);

    setPassportData(passportData);
    setStep('scanCompleted');
  }

  async function scan() {
    const check = checkInputs(passportNumber, dateOfBirth, dateOfExpiry)
    if (!check.success) {
      Toast.show({
        type: 'error',
        text1: check.message,
      })
      return
    }

    console.log('scanning...');
    setStep('scanning');

    if (Platform.OS === 'android') {
      scanAndroid();
    } else {
      scanIOS();
    }
  }

  async function scanAndroid() {
    try {
      const response = await PassportReader.scan({
        documentNumber: passportNumber,
        dateOfBirth: dateOfBirth,
        dateOfExpiry: dateOfExpiry,
      });
      console.log('response', response);
      console.log('scanned');
      handleResponseAndroid(response);
    } catch (e: any) {
      console.log('error during scan :', e);
      Toast.show({
        type: 'error',
        text1: e.message,
      })
    }
  }

  async function scanIOS() {
    try {
      const response = await NativeModules.PassportReader.scanPassport(
        passportNumber,
        dateOfBirth,
        dateOfExpiry
      );
      console.log('response', response);
      console.log('scanned');
      handleResponseIOS(response);
    } catch (e: any) {
      console.log('error during scan :', e);
      Toast.show({
        type: 'error',
        text1: e.message,
      })
    }
  }

  const handleProve = async () => {
    if (passportData === null) {
      console.log('passport data is null');
      return;
    }

    setGeneratingProof(true)
    await new Promise(resolve => setTimeout(resolve, 10));

    // 1. TODO check signature to make sure the proof will work

    // 2. Format all the data as inputs for the circuit
    const formattedMrz = formatMrz(passportData.mrz);
    const mrzHash = hash(formatMrz(passportData.mrz));

    const concatenatedDataHashes =
      Array.isArray(passportData.dataGroupHashes[0])
      ? formatAndConcatenateDataHashes(
        mrzHash,
        passportData.dataGroupHashes as DataHash[],
      )
      : passportData.dataGroupHashes
    
    
    const reveal_bitmap = Array.from({ length: 88 }, (_) => '0');

    for(const attribute in disclosure) {
      if (disclosure[attribute as keyof typeof disclosure]) {
        const [start, end] = attributeToPosition[attribute as keyof typeof attributeToPosition];
        for(let i = start; i <= end; i++) {
          reveal_bitmap[i] = '1';
        }
      }
    }

    if (!["SHA256withRSA", "sha256WithRSAEncryption"].includes(passportData.signatureAlgorithm)) {
      console.log(`${passportData.signatureAlgorithm} not supported for proof right now.`);
      setError(`${passportData.signatureAlgorithm} not supported for proof right now.`);
      return;
    }

    const inputs = {
      mrz: Array.from(formattedMrz).map(byte => String(byte)),
      reveal_bitmap: reveal_bitmap.map(byte => String(byte)),
      dataHashes: Array.from((concatenatedDataHashes as number[]).map(toUnsignedByte)).map(byte => String(byte)),
      eContentBytes: Array.from(passportData.eContent.map(toUnsignedByte)).map(byte => String(byte)),
      signature: splitToWords(
        BigInt(bytesToBigDecimal(passportData.encryptedDigest)),
        BigInt(64),
        BigInt(32)
      ),
      pubkey: splitToWords(
        BigInt(passportData.pubKey.modulus as string),
        BigInt(64),
        BigInt(32)
      ),
      address,
    }

    console.log('inputs', inputs)

    const start = Date.now();
    if (Platform.OS === 'android') {
      await proveAndroid(inputs);
    } else {
      await proveIOS(inputs);
    }
    const end = Date.now();
    console.log('Total proof time from frontend:', end - start);
    setTotalTime(end - start);
  };

  async function proveAndroid(inputs: any) {
    NativeModules.RNPassportReader.provePassport(inputs, (err: any, res: any) => {
      if (err) {
        console.error(err);
        setError(
          "err: " + err.toString(),
        );
        return
      }
      console.log("res", res);
      const parsedResponse = JSON.parse(res);
      console.log('parsedResponse', parsedResponse);
      console.log('parsedResponse.duration', parsedResponse.duration);

      const deserializedProof = JSON.parse(parsedResponse.serialized_proof);
      console.log('deserializedProof', deserializedProof);

      const deserializedInputs = JSON.parse(parsedResponse.serialized_inputs);
      console.log('deserializedInputs', deserializedInputs);
      
      setProofTime(parsedResponse.duration);

      setProof({
        proof: JSON.stringify(deserializedProof),
        inputs: JSON.stringify(deserializedInputs),
      });
      setGeneratingProof(false)
      setStep('proofGenerated');
    });
  }

  async function proveIOS(inputs: any) {
    try {
      console.log('running mopro init action')
      await NativeModules.Prover.runInitAction()

      console.log('running mopro prove action')
      const response = await NativeModules.Prover.runProveAction({
        ...inputs,
        address: [BigInt(address).toString()]
      })
      console.log('proof response:', response)
      const parsedResponse = JSON.parse(response)

      console.log('running mopro verify action')
      const res = await NativeModules.Prover.runVerifyAction()
      console.log('verify response:', res)
      
      setProof({
        proof: JSON.stringify(formatProofIOS(parsedResponse.proof)),
        inputs: JSON.stringify(formatInputsIOS(parsedResponse.inputs)),
      });

      // setProofTime(response.duration);
      setGeneratingProof(false)
      setStep('proofGenerated');
    } catch (err: any) {
      console.log('err', err);
      setError(
        "err: " + err.toString(),
      );
    }
  }


  const handleMint = async () => {
    setMinting(true)
    if (!proof?.proof || !proof?.inputs) {
      console.log('proof or inputs is null');
      return;
    }
    if (!contractAddresses.ProofOfPassport || !proofOfPassportArtefact.abi) {
      console.log('contracts addresses or abi not found');
      return;
    }

    // Format the proof and publicInputs as calldata for the verifier contract
    const p = JSON.parse(proof.proof);
    const i = JSON.parse(proof.inputs);
    // const p = {"a": ["16502577771187684977980616374304236605057905196561863637384296592370445017998", "3901861368174142739149849352179287633574688417834634300291202761562972709023"], "b": [["14543689684654938043989715590415160645004827219804187355799512446208262437248", "2758656853017552407340621959452084149765188239766723663849017782705599048610"], ["11277365272183899064677884160333958573750879878546952615484891009952508146334", "6233152645613613236466445508816847016425532566954931368157994995587995754446"]], "c": ["6117026818273543012196632774531089444191538074414171872462281003025766583671", "10261526153619394223629018490329697233150978685332753612996629076672112420472"]}
    // const i = ["0", "0", "0", "146183216590389235917737925524385821154", "43653084046336027166990", "21085389953176386480267", "56519161086598100699293", "15779090386165698845937", "23690430366843652392111", "22932463418406768540896", "51019038683800409078189", "50360649287615093470666", "47789371969706091489401", "15311247864741754764238", "20579290199534174842880", "1318168358802144844680228651107716082931624381008"]
    console.log('p', p);
    console.log('i', i);
    const cd = groth16ExportSolidityCallData(p, i);
    const callData = JSON.parse(`[${cd}]`);
    console.log('callData', callData);

    // format transaction
    // for now, we do it all on sepolia
    try {
      const provider = new ethers.JsonRpcProvider('https://gateway.tenderly.co/public/sepolia');
      const proofOfPassportOnSepolia = new ethers.Contract(contractAddresses.ProofOfPassport, proofOfPassportArtefact.abi, provider);

      const transactionRequest = await proofOfPassportOnSepolia
        .mint.populateTransaction(...callData);
      console.log('transactionRequest', transactionRequest);

      const response = await axios.post(AWS_ENDPOINT, {
        chain: "sepolia",
        tx_data: transactionRequest
      });
      console.log('response status', response.status)
      console.log('response data', response.data)
      setMintText(`Network: Sepolia. Transaction hash: ${response.data.hash}`)
      const receipt = await provider.waitForTransaction(response.data.hash);
      console.log('receipt', receipt)
      if (receipt?.status === 1) {
        Toast.show({
          type: 'success',
          text1: 'Proof of passport minted',
        })
        setMintText(`SBT minted. Network: Sepolia. Transaction hash: ${response.data.hash}`)
      } else {
        Toast.show({
          type: 'error',
          text1: 'Proof of passport minting failed',
        })
        setMintText(`Error minting SBT. Network: Sepolia. Transaction hash: ${response.data.hash}`)
      }
    } catch (err: any) {
      console.log('err', err);
      if (err.isAxiosError && err.response) {
        const errorMessage = err.response.data.error
        console.log('Server error message:', errorMessage);

        // parse blockchain error and show it
        const match = errorMessage.match(/execution reverted: "([^"]*)"/);
        if (match && match[1]) {
          console.log('Parsed blockchain error:', match[1]);
          Toast.show({
            type: 'error',
            text1: `Error: ${match[1]}`,
          })
        } else {
          Toast.show({
            type: 'error',
            text1: `Error: mint failed`,
          })
          console.log('Failed to parse blockchain error');
        }
      }
      setMintText(`Error minting SBT. Network: Sepolia.`)
    }
  };

  return (
    <GluestackUIProvider config={config}>
      <SafeAreaView style={backgroundStyle}>
        <StatusBar
          barStyle={isDarkMode ? 'light-content' : 'dark-content'}
          backgroundColor={Colors.red}
        />
        <ScrollView
          contentInsetAdjustmentBehavior="automatic"
          style={{
            backgroundColor: isDarkMode ? Colors.black : Colors.black,
          }}
          contentContainerStyle={{ flexGrow: 1 }}
        >
          <View style={styles.view}>
            {step === 'enterDetails' ? (
                      <EnterDetailsScreen
                      passportNumber={passportNumber}
                      setPassportNumber={setPassportNumber}
                      dateOfBirth={dateOfBirth}
                      setDateOfBirth={setDateOfBirth}
                      dateOfExpiry={dateOfExpiry}
                      setDateOfExpiry={setDateOfExpiry}
                      onScanPress={scan}
                      onStartCameraScan={startCameraScan}
                    />
            ) : null}
            {step === 'scanning' ? (
              <View style={styles.sectionContainer}>
                <Text style={styles.header}>Put your phone on your passport</Text>
                <Spinner
                  size={60}
                  style={{marginTop: 70}}
                />
              </View>
            ) : null}
            {step === 'scanCompleted' && passportData ? (
              <View style={styles.sectionContainer}>
                <Text style={styles.header}>
                  Hi {getFirstName(passportData.mrz)}
                </Text>
                <View
                  marginTop={20}
                  marginBottom={20}
                >
                  <Text
                    marginBottom={5}
                  >
                    Signature algorithm: {passportData.signatureAlgorithm}
                  </Text>
                  <Text
                    marginBottom={10}
                  >
                    What do you want to disclose ?
                  </Text>
                  {Object.keys(disclosure).map((key) => {
                    const keyy = key as keyof typeof disclosure;
                    const indexes = attributeToPosition[keyy];
                    const keyFormatted = keyy.replace(/_/g, ' ').split(' ').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                    const mrzAttribute = passportData.mrz.slice(indexes[0], indexes[1])
                    const mrzAttributeFormatted = mrzAttribute.replace(/</g, ' ')
                    
                    return (
                      <View key={key} margin={2} width={"$full"} flexDirection="row" justifyContent="space-between">
                        <View maxWidth={"$5/6"}>
                          <Text
                            style={{fontWeight: "bold"}}
                          >
                            {keyFormatted}:{" "}
                          </Text>
                          <Text>
                            {mrzAttributeFormatted}
                          </Text>
                        </View>
                        <Checkbox
                          value={key}
                          isChecked={disclosure[keyy]}
                          onChange={() => handleDisclosureChange(keyy)}
                          size="lg"
                          aria-label={key}
                        >
                          <CheckboxIndicator mr="$2">
                            <CheckboxIcon as={CheckIcon} />
                          </CheckboxIndicator>
                        </Checkbox>
                      </View>
                    )
                  })}
                </View>
                <Text>Enter your address or ens</Text>
                <Input
                  variant="outline"
                  size="md"
                  marginBottom={10}
                  marginTop={4}
                >
                  <InputField
                    value={address}
                    onChangeText={setAddress}
                    placeholder="Your Address or ens name"
                  />
                </Input>

                {generatingProof ?
                  <Button
                    onPress={handleProve}
                  >
                    <ButtonSpinner mr="$1" />
                    <ButtonText>Generating zk proof</ButtonText>
                  </Button>
                  : <Button
                      onPress={handleProve}
                    >
                      <ButtonText>Generate zk proof</ButtonText>
                    </Button>
                }
              </View>
            ) : null}
            {step === 'proofGenerated' ? (
              <View style={styles.sectionContainer}>
                <Text style={styles.header}>Zero-knowledge proof generated</Text>

                <Text style={{fontWeight: "bold"}}>
                  Proof:
                </Text>
                <Text>
                  {JSON.stringify(proof)}
                </Text>

                <Text>
                  <Text style={{ fontWeight: 'bold' }}>Proof Duration:</Text> {formatDuration(proofTime)}
                </Text>     
                <Text>
                  <Text style={{ fontWeight: 'bold' }}>Total Duration:</Text> {formatDuration(totalTime)}
                </Text>

                <Button
                  onPress={handleMint}
                  marginTop={10}
                >
                  <ButtonText>Mint Proof of Passport</ButtonText>
                </Button>
                {mintText && <Text>
                  {mintText}
                </Text>}
              </View>
            ) : null}
          </View>
          <View style={{...styles.sectionContainer, ...styles.testSection, marginTop: 20}}>
            <Text style={{...styles.sectionDescription, textAlign: "center"}}>Test functions</Text>

            <Button
              onPress={async () => {
                NativeModules.RNPassportReader.callRustLib((err: any, res: any) => {
                  if (err) {
                    console.error(err);
                    setTestResult(err);
                  } else {
                    console.log(res); // Should log "5"
                    setTestResult(res);
                  }
                });
              }}
              marginTop={10}
            >
              <ButtonText>Call arkworks lib</ButtonText>
            </Button>
            {testResult && <Text>{testResult}</Text>}

          </View>
        </ScrollView>
      </SafeAreaView>
      <Toast config={toastConfig} />
    </GluestackUIProvider>
  );
}

const styles = StyleSheet.create({
  view: {
    flex: 1,
  },
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
    fontSize: 22,
    fontWeight: 'bold',
    textAlign: 'center',
    marginTop: 20,
  },
  testSection: {
    backgroundColor: '#f2f2f2', // different background color
    padding: 10,
    borderTopWidth: 1,
    borderTopColor: '#dcdcdc', // adding a border top with a light color
    marginTop: 15,
  },
});

export default App;


export const toastConfig = {
  info: (props: ToastProps) => (
    <BaseToast
      {...props}
      contentContainerStyle={{ paddingHorizontal: 15 }}
      text1Style={{
        fontSize: 15,
        fontWeight: "600",
      }}
      text2Style={{
        fontSize: 15,
        fontWeight: "500",
      }}
    />
  ),
  error: (props: ToastProps) => (
    <ErrorToast
      {...props}
      contentContainerStyle={{ paddingHorizontal: 15}}
      text1Style={{
        fontSize: 15,
        fontWeight: "600",
      }}
      text2Style={{
        fontSize: 15,
        fontWeight: "400",
      }}
    />
  ),
  success: (props: ToastProps) => (
    <SuccessToast
      {...props}
      contentContainerStyle={{ paddingHorizontal: 15 }}
      text1Style={{
        fontSize: 15,
        fontWeight: "600",
      }}
      text2Style={{
        fontSize: 15,
        fontWeight: "400",
      }}
    />
  ),
};
