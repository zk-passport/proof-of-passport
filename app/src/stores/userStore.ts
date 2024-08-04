import { create } from 'zustand'
import {
  DEFAULT_PNUMBER,
  DEFAULT_DOB,
  DEFAULT_DOE,
} from '@env';
import { mockPassportData_sha256WithRSAEncryption_65537 } from '../../../common/src/utils/mockPassportData';
import { PassportData } from '../../../common/src/utils/types';
import * as Keychain from 'react-native-keychain';
import * as amplitude from '@amplitude/analytics-react-native';
import useNavigationStore from './navigationStore';
import { Steps } from '../utils/utils';
import { downloadZkey } from '../utils/zkeyDownload';
import { generateCircuitInputsRegister } from '../../../common/src/utils/generateInputs';
import { PASSPORT_ATTESTATION_ID, RPC_URL, SignatureAlgorithm } from '../../../common/src/constants/constants';
import { generateProof } from '../utils/prover';
import { formatSigAlgNameForCircuit } from '../../../common/src/utils/utils';
import { sendRegisterTransaction } from '../utils/transactions';
import { loadPassportData, loadSecret, loadSecretOrCreateIt, storePassportData } from '../utils/keychain';
import { ethers } from 'ethers';
import { isCommitmentRegistered } from '../utils/registration';
import { formatAsVC } from '../../../common/src/utils/formatVC';

interface UserState {
  passportNumber: string
  dateOfBirth: string
  dateOfExpiry: string
  registered: boolean
  passportData: PassportData
  secret: string
  initUserStore: () => void
  registerPassportData: (passportData: PassportData) => void
  registerCommitment: (passportData?: PassportData) => void
  clearPassportDataFromStorage: () => void
  clearSecretFromStorage: () => void
  update: (patch: any) => void
  deleteMrzFields: () => void
}

const useUserStore = create<UserState>((set, get) => ({
  passportNumber: DEFAULT_PNUMBER ?? "",
  dateOfBirth: DEFAULT_DOB ?? "",
  dateOfExpiry: DEFAULT_DOE ?? "",

  registered: false,
  passportData: mockPassportData_sha256WithRSAEncryption_65537,
  secret: "",

  // When user opens the app, checks presence of passportData
  // - If passportData is not present, starts the onboarding flow
  // - If passportData is present, then secret must be here too (they are always set together). Request the tree.
  // 	- If the commitment is present in the tree, proceed to main screen
  // 	- If the commitment is not present in the tree, proceed to main screen AND try registering it in the background
  initUserStore: async () => {
    // download zkeys if they are not already downloaded
    downloadZkey("register_sha256WithRSAEncryption_65537"); // might move after nfc scanning
    downloadZkey("disclose");

    const secret = await loadSecretOrCreateIt();
    set({ secret });

    const passportData = await loadPassportData();
    if (!passportData) {
      console.log("No passport data found, starting onboarding flow")
      return;
    }

    const isAlreadyRegistered = await isCommitmentRegistered(secret, JSON.parse(passportData));

    if (!isAlreadyRegistered) {
      console.log("not registered but passport data found, skipping to nextScreen")
      set({
        passportData: JSON.parse(passportData),
      });
      useNavigationStore.getState().setStep(Steps.NEXT_SCREEN);
      return;
    }

    console.log("registered and passport data found, skipping to app selection screen")
    set({
      passportData: JSON.parse(passportData),
      registered: true,
    });
    useNavigationStore.getState().setStep(Steps.REGISTERED);
  },

  // When reading passport for the first time:
  // - Check presence of secret. If there is none, create one and store it
  // 	- Store the passportData and try registering the commitment in the background
  registerPassportData: async (passportData) => {
    const alreadyStoredPassportData = await loadPassportData();

    if (alreadyStoredPassportData) {
      console.log("passportData is already stored, this should never happen in prod")
      console.log("replacing it with the new one")
    }

    await storePassportData(passportData)
    set({ passportData });
  },

  registerCommitment: async (mockPassportData?: PassportData) => {
    const {
      toast,
      setStep,
      update: updateNavigationStore,
    } = useNavigationStore.getState();
    const secret = await loadSecret() as string;
    let passportData = get().passportData
    if (mockPassportData) {
      passportData = mockPassportData
    }

    const isAlreadyRegistered = await isCommitmentRegistered(secret, passportData);
    if (isAlreadyRegistered) {
      console.log("commitment is already registered")
      toast.show('Identity already registered, skipping', {
        customData: {
          type: "info",
        },
      })
      set({ registered: true });
      setStep(Steps.REGISTERED);
      return;
    }

    try {
      const inputs = generateCircuitInputsRegister(
        secret,
        PASSPORT_ATTESTATION_ID,
        passportData,
        [mockPassportData_sha256WithRSAEncryption_65537]
      );

      amplitude.track(`Sig alg supported: ${passportData.signatureAlgorithm}`);

      Object.keys(inputs).forEach((key) => {
        if (Array.isArray(inputs[key as keyof typeof inputs])) {
          console.log(key, inputs[key as keyof typeof inputs].slice(0, 10), '...');
        } else {
          console.log(key, inputs[key as keyof typeof inputs]);
        }
      });

      const start = Date.now();

      const sigAlgFormatted = formatSigAlgNameForCircuit(passportData.signatureAlgorithm, passportData.pubKey.exponent);
      const sigAlgIndex = SignatureAlgorithm[sigAlgFormatted as keyof typeof SignatureAlgorithm]

      const proof = await generateProof(
        `register_${sigAlgFormatted}`,
        inputs,
      );

      console.log('proof:', proof);

      const end = Date.now();
      console.log('Total proof time from frontend:', end - start);
      amplitude.track('Proof generation successful, took ' + ((end - start) / 1000) + ' seconds');

      const provider = new ethers.JsonRpcProvider(RPC_URL);

      const serverResponse = await sendRegisterTransaction(proof, sigAlgIndex)
      const txHash = serverResponse?.data.hash;

      const receipt = await provider.waitForTransaction(txHash);
      console.log('receipt status:', receipt?.status);

      if (receipt?.status === 0) {
        throw new Error("Transaction failed");
      }

      set({ registered: true });
      setStep(Steps.REGISTERED);
    } catch (error: any) {
      console.error(error);
      updateNavigationStore({
        showRegistrationErrorSheet: true,
        registrationErrorMessage: error.message,
      })
      setStep(Steps.NEXT_SCREEN);
      amplitude.track(error.message);
    }
  },

  clearPassportDataFromStorage: async () => {
    await Keychain.resetGenericPassword({ service: "passportData" });
  },

  clearSecretFromStorage: async () => {
    await Keychain.resetGenericPassword({ service: "secret" });
  },

  update: (patch) => {
    set({
      ...get(),
      ...patch,
    });
  },

  deleteMrzFields: () => set({
    passportNumber: "",
    dateOfBirth: "",
    dateOfExpiry: "",
  }),
}))
// Function to generate an attestation formatted as a verifiable credential
const generateAttestation = (passportData) => {
    const credentialSubject = { passportData, attestationId: PASSPORT_ATTESTATION_ID };
    return formatAsVC(credentialSubject);
};

export default useUserStore
