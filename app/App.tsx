import React, { useEffect, useState } from 'react';
import {
  NativeModules,
  DeviceEventEmitter,
} from 'react-native';
import Toast from 'react-native-toast-message';
import {
  DEFAULT_PNUMBER,
  DEFAULT_DOB,
  DEFAULT_DOE
} from '@env';
import { PassportData } from '../common/src/utils/types';
import { samplePassportData } from '../common/src/utils/passportDataStatic';
import "@ethersproject/shims"
import { ethers } from "ethers";
import MainScreen from './src/screens/MainScreen';
import { Steps } from './src/utils/utils';
import { startCameraScan } from './src/utils/cameraScanner';
import { scan } from './src/utils/nfcScanner';
import { mint } from './src/utils/minter';
import { toastConfig } from './src/utils/toastConfig';
import { Buffer } from 'buffer';
import { YStack } from 'tamagui';
import { prove } from './src/utils/prover';
global.Buffer = Buffer;

console.log('DEFAULT_PNUMBER', DEFAULT_PNUMBER);

function App(): JSX.Element {
  const [passportNumber, setPassportNumber] = useState(DEFAULT_PNUMBER ?? "");
  const [dateOfBirth, setDateOfBirth] = useState(DEFAULT_DOB ?? '');
  const [dateOfExpiry, setDateOfExpiry] = useState(DEFAULT_DOE ?? '');
  const [address, setAddress] = useState<string>(ethers.ZeroAddress);
  const [passportData, setPassportData] = useState<PassportData>(samplePassportData as PassportData);
  const [step, setStep] = useState<number>(Steps.MRZ_SCAN);
  const [generatingProof, setGeneratingProof] = useState<boolean>(false);
  const [proofTime, setProofTime] = useState<number>(0);
  const [proof, setProof] = useState<{ proof: string, inputs: string } | null>(null);
  const [mintText, setMintText] = useState<string>("");
  const [majority, setMajority] = useState<number>(18);

  const [disclosure, setDisclosure] = useState({
    issuing_state: false,
    name: false,
    passport_number: false,
    nationality: false,
    date_of_birth: false,
    gender: false,
    expiry_date: false,
    older_than: false,
  });

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
    init()
  }, []);

  async function init() {
    await new Promise(resolve => setTimeout(resolve, 2000));
    console.log('launching init')
    const res = await NativeModules.Prover.runInitAction()
    console.log('init done')
    console.log('init res', res)
  }

  const handleStartCameraScan = () => {
    startCameraScan({
      setPassportNumber,
      setDateOfBirth,
      setDateOfExpiry,
      setStep,
    });
  };


  const handleNFCScan = () => {
    scan({
      passportNumber,
      dateOfBirth,
      dateOfExpiry,
      setPassportData,
      setStep,
    });
  };

  const handleProve = (path: string) => {
    prove({
      passportData,
      disclosure,
      address,
      setStep,
      setGeneratingProof,
      setProofTime,
      setProof,
    }, path);
  };

  const handleMint = () => {
    mint({
      proof,
      setStep,
      setMintText,
    });
  };

  return (
    <YStack f={1} bc="#161616" h="100%" w="100%">
      <YStack h="100%" w="100%">
        <MainScreen
          onStartCameraScan={handleStartCameraScan}
          nfcScan={handleNFCScan}
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
          majority={majority}
          setMajority={setMajority}
        />
      </YStack>
      <Toast config={toastConfig} />
    </YStack>
  );
}

export default App;
