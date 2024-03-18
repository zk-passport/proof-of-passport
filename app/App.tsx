import React, { useEffect, useState } from 'react';
import {
  NativeModules,
  DeviceEventEmitter,
  Platform,
} from 'react-native';
import Toast, { BaseToast, ErrorToast, SuccessToast, ToastProps } from 'react-native-toast-message';
// @ts-ignore
import PassportReader from 'react-native-passport-reader';
import { checkInputs } from './utils/utils';
import {
  DEFAULT_PNUMBER,
  DEFAULT_DOB,
  DEFAULT_DOE
} from '@env';
import { PassportData } from '../common/src/utils/types';
import { RELAYER_URL, MAX_DATAHASHES_LEN } from '../common/src/constants/constants';
import {
  toUnsignedByte,
  bytesToBigDecimal,
  formatMrz,
  splitToWords,
  formatProofIOS,
  formatInputsIOS
} from '../common/src/utils/utils';
import { samplePassportData } from '../common/src/utils/passportDataStatic';
import { sha256Pad } from '../common/src/utils/sha256Pad';

import "@ethersproject/shims"
import { ethers } from "ethers";
import axios from 'axios';
import groth16ExportSolidityCallData from './utils/snarkjs';
import contractAddresses from "./deployments/addresses.json"
import proofOfPassportArtefact from "./deployments/ProofOfPassport.json";
import MainScreen from './src/screens/MainScreen';
import { extractMRZInfo, formatDateToYYMMDD, Steps } from './src/utils/utils';
import forge from 'node-forge';
import { Buffer } from 'buffer';
import { YStack } from 'tamagui';
global.Buffer = Buffer;


console.log('DEFAULT_PNUMBER', DEFAULT_PNUMBER);

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
  const [passportNumber, setPassportNumber] = useState(DEFAULT_PNUMBER ?? "");
  const [dateOfBirth, setDateOfBirth] = useState(DEFAULT_DOB ?? '');
  const [dateOfExpiry, setDateOfExpiry] = useState(DEFAULT_DOE ?? '');
  const [address, setAddress] = useState<string>(ethers.ZeroAddress);
  const [passportData, setPassportData] = useState<PassportData>(samplePassportData as PassportData);
  const [step, setStep] = useState<number>(Steps.MRZ_SCAN);
  const [error, setError] = useState<any>(null);
  const [generatingProof, setGeneratingProof] = useState<boolean>(false);
  const [proofTime, setProofTime] = useState<number>(0);
  const [proof, setProof] = useState<{ proof: string, inputs: string } | null>(null);
  const [minting, setMinting] = useState<boolean>(false);
  const [mintText, setMintText] = useState<string>("");
  const [initCompleted, setInitCompleted] = useState(false);

  const [disclosure, setDisclosure] = useState({
    issuing_state: false,
    name: false,
    passport_number: false,
    nationality: false,
    date_of_birth: false,
    gender: false,
    expiry_date: false,
  });

  const { MRZScannerModule } = NativeModules;

  const startCameraScan = async () => {
    if (Platform.OS === 'ios') {
      try {
        const result = await MRZScannerModule.startScanning();
        console.log("Scan result:", result);
        console.log(`Document Number: ${result.documentNumber}, Expiry Date: ${result.expiryDate}, Birth Date: ${result.birthDate}`);
        setPassportNumber(result.documentNumber);
        setDateOfBirth(formatDateToYYMMDD(result.birthDate));
        setDateOfExpiry(formatDateToYYMMDD(result.expiryDate));
      } catch (e) {
        console.error(e);
      }
    }
    else {
      NativeModules.CameraActivityModule.startCameraActivity()
        .then((mrzInfo: string) => {
          try {
            const { documentNumber, birthDate, expiryDate } = extractMRZInfo(mrzInfo);
            setPassportNumber(documentNumber);
            setDateOfBirth(birthDate);
            setDateOfExpiry(expiryDate);
            setStep(Steps.MRZ_SCAN_COMPLETED);
          } catch (error: any) {
            console.error('Invalid MRZ format:', error.message);
          }
        })
        .catch((error: any) => {
          console.error('Camera Activity Error:', error);
        });
    }
  };


  const handleDisclosureChange = (field: string) => {
    setDisclosure(
      {
        ...disclosure,
        [field]: !disclosure[field as keyof typeof disclosure]
      });
  };

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
      initMopro()
    }
  }, []);

  const initMopro = async () => {
    try {
      await NativeModules.Prover.runInitAction();
      setInitCompleted(true);
      console.log('Mopro initialization completed');
    } catch (error) {
      console.error('Mopro initialization failed:', error);
    }
  };

  async function handleResponseIOS(response: any) {
    const parsed = JSON.parse(response);

    const eContentBase64 = parsed.eContentBase64; // this is what we call concatenatedDataHashes in android world
    const signedAttributes = parsed.signedAttributes; // this is what we call eContent in android world
    const signatureAlgorithm = parsed.signatureAlgorithm;
    const mrz = parsed.passportMRZ;
    const signatureBase64 = parsed.signatureBase64;
    console.log('dataGroupsPresent', parsed.dataGroupsPresent)
    console.log('placeOfBirth', parsed.placeOfBirth)
    console.log('activeAuthenticationPassed', parsed.activeAuthenticationPassed)
    console.log('isPACESupported', parsed.isPACESupported)
    console.log('isChipAuthenticationSupported', parsed.isChipAuthenticationSupported)
    console.log('residenceAddress', parsed.residenceAddress)
    console.log('passportPhoto', parsed.passportPhoto.substring(0, 100) + '...')
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
      photoBase64: "data:image/jpeg;base64," + parsed.passportPhoto,
    };

    console.log('mrz', passportData.mrz);
    console.log('signatureAlgorithm', passportData.signatureAlgorithm);
    console.log('pubKey', passportData.pubKey);
    console.log('dataGroupHashes', passportData.dataGroupHashes);
    console.log('eContent', passportData.eContent);
    console.log('encryptedDigest', passportData.encryptedDigest);
    console.log("photoBase64", passportData.photoBase64.substring(0, 100) + '...')

    setPassportData(passportData);
    setStep(Steps.NFC_SCAN_COMPLETED);
  }

  async function handleResponseAndroid(response: any) {
    const {
      mrz,
      signatureAlgorithm,
      modulus,
      curveName,
      publicKeyQ,
      eContent,
      encryptedDigest,
      photo,
      digestAlgorithm,
      signerInfoDigestAlgorithm,
      digestEncryptionAlgorithm,
      LDSVersion,
      unicodeVersion,
      encapContent
    } = response;

    const passportData: PassportData = {
      mrz: mrz.replace(/\n/g, ''),
      signatureAlgorithm: signatureAlgorithm,
      pubKey: {
        modulus: modulus,
        curveName: curveName,
        publicKeyQ: publicKeyQ,
      },
      dataGroupHashes: JSON.parse(encapContent),
      eContent: JSON.parse(eContent),
      encryptedDigest: JSON.parse(encryptedDigest),
      photoBase64: photo.base64,
    };

    console.log('mrz', passportData.mrz);
    console.log('signatureAlgorithm', passportData.signatureAlgorithm);
    console.log('pubKey', passportData.pubKey);
    console.log('dataGroupHashes', passportData.dataGroupHashes);
    console.log('eContent', passportData.eContent);
    console.log('encryptedDigest', passportData.encryptedDigest);
    console.log("photoBase64", passportData.photoBase64.substring(0, 100) + '...')
    console.log("digestAlgorithm", digestAlgorithm)
    console.log("signerInfoDigestAlgorithm", signerInfoDigestAlgorithm)
    console.log("digestEncryptionAlgorithm", digestEncryptionAlgorithm)
    console.log("LDSVersion", LDSVersion)
    console.log("unicodeVersion", unicodeVersion)
    console.log("encapContent", encapContent)

    setPassportData(passportData);
    setStep(Steps.NFC_SCAN_COMPLETED);
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
    setStep(Steps.NFC_SCANNING);

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
      // console.log('response', response);
      console.log('scanned');
      handleResponseAndroid(response);
    } catch (e: any) {
      console.log('error during scan :', e);
      setStep(Steps.MRZ_SCAN_COMPLETED);
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
      setStep(Steps.MRZ_SCAN_COMPLETED);
      Toast.show({
        type: 'error',
        text1: e.message,
      })
    }
  }

  const handleProve = async (path: string) => {
    setStep(Steps.GENERATING_PROOF);
    if (passportData === null) {
      console.log('passport data is null');
      return;
    }

    setGeneratingProof(true)
    await new Promise(resolve => setTimeout(resolve, 10));

    // 1. TODO check signature to make sure the proof will work

    // 2. Format all the data as inputs for the circuit
    const formattedMrz = formatMrz(passportData.mrz);

    const reveal_bitmap = Array.from({ length: 88 }, (_) => '0');

    for (const attribute in disclosure) {
      if (disclosure[attribute as keyof typeof disclosure]) {
        const [start, end] = attributeToPosition[attribute as keyof typeof attributeToPosition];
        for (let i = start; i <= end; i++) {
          reveal_bitmap[i] = '1';
        }
      }
    }

    // if (!["SHA256withRSA", "sha256WithRSAEncryption"].includes(passportData.signatureAlgorithm)) {
    //   console.log(`${passportData.signatureAlgorithm} not supported for proof right now.`);
    //   setError(`${passportData.signatureAlgorithm} not supported for proof right now.`);
    //   return;
    // }

    console.log('passportData.dataGroupHashes', passportData.dataGroupHashes);

    const dataGroupHashesUint8Array = new Uint8Array(passportData.dataGroupHashes);

    console.log('dataGroupHashesUint8Array', dataGroupHashesUint8Array);

    const [messagePadded, messagePaddedLen] = sha256Pad(
      dataGroupHashesUint8Array,
      MAX_DATAHASHES_LEN
    );
    console.log('messagePadded', messagePadded);

    const inputs = {
      mrz: Array.from(formattedMrz).map(byte => String(byte)),
      reveal_bitmap: reveal_bitmap.map(byte => String(byte)),
      dataHashes: Array.from(messagePadded).map((x) => (x as number).toString()),
      datahashes_padded_length: messagePaddedLen.toString(),
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
      await proveAndroid(inputs, path);
    } else {
      await proveIOS(inputs);
    }
    const end = Date.now();
    console.log('Total proof time from frontend:', end - start);
  };

  async function proveAndroid(inputs: any, path: string) {
    const startTime = Date.now();
    NativeModules.RNPassportReader.provePassport(inputs, path, (err: any, res: any) => {
      const endTime = Date.now();
      setProofTime(endTime - startTime);

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

      const deserializedProof = JSON.parse(parsedResponse.serialized_proof);
      console.log('deserializedProof', deserializedProof);

      const deserializedInputs = JSON.parse(parsedResponse.serialized_inputs);
      console.log('deserializedInputs', deserializedInputs);

      setProof({
        proof: JSON.stringify(deserializedProof),
        inputs: JSON.stringify(deserializedInputs),
      });
      setGeneratingProof(false);
      setStep(Steps.PROOF_GENERATED);
    });
  }

  async function proveIOS(inputs: any) {
    // Wait for initialization to complete with a 1 minute timeout
    const waitForInit = async (timeoutMs = 60000) => {
      const startTime = Date.now();
      while (!initCompleted && Date.now() - startTime < timeoutMs) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait for 1 second before checking again
      }
      return initCompleted;
    };

    const initSuccess = await waitForInit();
    if (!initSuccess) {
      console.log('Initialization did not complete within the timeout. Please check if Mopro is initializing properly.');
      Toast.show({
        type: 'error',
        text1: 'Initialization failed to complete before timeout',
      })
      return;
    }
    
    try {
      const startTime = Date.now();
      console.log('running mopro prove action')
      const response = await NativeModules.Prover.runProveAction({
        ...inputs,
        datahashes_padded_length: [inputs.datahashes_padded_length.toString()], // wrap everything in arrays for bindings 
        address: [BigInt(address).toString()]
      })
      console.log('proof response:', response)
      const parsedResponse = JSON.parse(response)

      const endTime = Date.now();
      setProofTime(endTime - startTime);

      console.log('running mopro verify action')
      const res = await NativeModules.Prover.runVerifyAction()
      console.log('verify response:', res)

      setProof({
        proof: JSON.stringify(formatProofIOS(parsedResponse.proof)),
        inputs: JSON.stringify(formatInputsIOS(parsedResponse.inputs)),
      });

      setGeneratingProof(false)
      setStep(Steps.PROOF_GENERATED);
    } catch (err: any) {
      console.log('err', err);
      setError(
        "err: " + err.toString(),
      );
    }
  }


  const handleMint = async () => {
    setStep(Steps.TX_MINTING);
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

      const response = await axios.post(RELAYER_URL, {
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
          text1: 'SBT minted 🎊',
          position: 'top',
          bottomOffset: 80,
        })
        setMintText(`SBT minted. Network: Sepolia. Transaction hash: ${response.data.hash}`)
        setStep(Steps.TX_MINTED);
      } else {
        Toast.show({
          type: 'error',
          text1: 'Proof of passport minting failed',
          position: 'top',
          bottomOffset: 80,
        })
        setMintText(`Error minting SBT. Network: Sepolia. Transaction hash: ${response.data.hash}`)
        setStep(Steps.PROOF_GENERATED);
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
            position: 'top',
            bottomOffset: 80,
          })
        } else {
          Toast.show({
            type: 'error',
            text1: `Error: mint failed`,
            position: 'top',
            bottomOffset: 80,
          })
          console.log('Failed to parse blockchain error');
        }
      }
      setMintText(`Error minting SBT. Network: Sepolia.`)
    }
  };

  return (
    <YStack f={1} bg="white" h="100%" w="100%">
      <YStack h="100%" w="100%">
        <MainScreen
          onStartCameraScan={startCameraScan}
          nfcScan={scan}
          passportData={passportData}
          disclosure={disclosure}
          handleDisclosureChange={handleDisclosureChange}
          address={address}
          setAddress={setAddress}
          generatingProof={generatingProof}
          handleProve={handleProve}
          step={step}
          mintText={mintText}
          proof={proof}
          proofTime={proofTime}
          handleMint={handleMint}
          setStep={setStep}
          passportNumber={passportNumber}
          setPassportNumber={setPassportNumber}
          dateOfBirth={dateOfBirth}
          setDateOfBirth={setDateOfBirth}
          dateOfExpiry={dateOfExpiry}
          setDateOfExpiry={setDateOfExpiry}
          initCompleted={initCompleted}
        />
      </YStack>
      <Toast config={toastConfig} />
    </YStack>
  );
}

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
