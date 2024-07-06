pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/utils/bytes.circom";
include "./passport_verifier_sha512WithRSAEncryption_65537.circom";
include "binary-merkle-root.circom";
include "./utils/splitSignalsToWords.circom";

template Register_sha512WithRSAEncryption_65537(n, k, max_datahashes_bytes, nLevels, signatureAlgorithm) {
    signal input secret;

    signal input mrz[93];
    signal input dg1_hash_offset;
    signal input econtent[max_datahashes_bytes];
    signal input datahashes_padded_length;
    signal input signed_attributes[104];
    signal input signature[k];
    signal input dsc_modulus[k];
    signal input dsc_secret;
    signal input attestation_id;

    component splitSignalsToWords_modulus = SplitSignalsToWords(n,k,230,9); // TODO refactor and create assertion that 121*17 < 254 * 9 and 254 <= 254
    component splitSignalsToWords_signature = SplitSignalsToWords(n,k,230,9); // TODO refactor and create assertion that 121*17 < 254 * 9 and 254 <= 254
    splitSignalsToWords_modulus.in <== dsc_modulus;
    splitSignalsToWords_signature.in <== signature;

    component dsc_commitment_hasher = Poseidon(10);
    component nullifier_hasher = Poseidon(10);
    component leaf_hasher = Poseidon(10);
    dsc_commitment_hasher.inputs[0] <== dsc_secret;
    nullifier_hasher.inputs[0] <== secret;
    leaf_hasher.inputs[0] <== signatureAlgorithm;
    for (var i= 0; i < 9; i++) {
        dsc_commitment_hasher.inputs[i+1] <== splitSignalsToWords_modulus.out[i];
        leaf_hasher.inputs[i+1] <== splitSignalsToWords_modulus.out[i];
        nullifier_hasher.inputs[i+1] <== splitSignalsToWords_signature.out[i];
    }
    signal output blinded_dsc_commitment <== dsc_commitment_hasher.out;
    signal output nullifier <== nullifier_hasher.out;

    // Verify passport validity
    component PV = PassportVerifier_sha512WithRSAEncryption_65537(n, k, max_datahashes_bytes);
    PV.mrz <== mrz;
    PV.dg1_hash_offset <== dg1_hash_offset;
    PV.dataHashes <== econtent;
    PV.datahashes_padded_length <== datahashes_padded_length;
    PV.eContentBytes <== signed_attributes;
    PV.dsc_modulus <== dsc_modulus;
    PV.signature <== signature;

    // Generate the commitment
    component poseidon_hasher = Poseidon(6);
    poseidon_hasher.inputs[0] <== secret;
    poseidon_hasher.inputs[1] <== attestation_id;
    poseidon_hasher.inputs[2] <== leaf_hasher.out;

    signal mrz_packed[3] <== PackBytes(93)(mrz);
    for (var i = 0; i < 3; i++) {
        poseidon_hasher.inputs[i + 3] <== mrz_packed[i];
    }
    signal output commitment <== poseidon_hasher.out;

}

// We hardcode 10 here for sha512WithRSAEncryption_65537
component main { public [ attestation_id ] } = Register_sha512WithRSAEncryption_65537(121, 17, 320, 16, 10);
