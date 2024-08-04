import axios from "axios";
import { COMMITMENT_TREE_TRACKER_URL, PASSPORT_ATTESTATION_ID } from "../../../common/src/constants/constants";
import { LeanIMT } from "@zk-kit/imt";
import { poseidon2, poseidon6 } from "poseidon-lite";
import { PassportData } from "../../../common/src/utils/types";
import { getLeaf } from "../../../common/src/utils/pubkeyTree";
import { formatMrz, packBytes } from "../../../common/src/utils/utils";
import { findIndexInTree } from "../../../common/src/utils/generateInputs";
import { formatAsVC } from '../../../common/src/utils/formatVC';

export async function isCommitmentRegistered(secret: string, passportData: PassportData) {
  const response = await axios.get(COMMITMENT_TREE_TRACKER_URL)
  console.log('response.data:', response.data);

  const imt = new LeanIMT(
    (a: bigint, b: bigint) => poseidon2([a, b]),
    []
  );

  imt.import(response.data);

  const pubkey_leaf = getLeaf({
    signatureAlgorithm: passportData.signatureAlgorithm,
    modulus: passportData.pubKey.modulus,
    exponent: passportData.pubKey.exponent,
  });

  const formattedMrz = formatMrz(passportData.mrz);
  const mrz_bytes = packBytes(formattedMrz);
  const commitment = poseidon6([
    secret,
    PASSPORT_ATTESTATION_ID,
    pubkey_leaf,
    mrz_bytes[0],
    mrz_bytes[1],
    mrz_bytes[2]
  ]);

  console.log('commitment', commitment.toString());

  try {
    findIndexInTree(imt as any, commitment); // this will throw if not found
    return true
  } catch(err) {
    return false;
  }
}

// New function to register the user and generate a verifiable credential
export const registerUser = (passportData: PassportData) => {
  const credentialSubject = {
    passportData, 
    attestationId: PASSPORT_ATTESTATION_ID 
  };
  const vc = formatAsVC(credentialSubject);
  console.log(vc);
};
