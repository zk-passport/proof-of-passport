pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/utils/bytes.circom";
include "isOlderThan.circom";
include "isValid.circom";
include "binary-merkle-root.circom";

template ValidatePassport(nLevels) {
    signal input secret;
    signal input attestation_id;
    signal input pubkey_leaf;
    signal input mrz[93];

    signal input merkle_root;
    signal input merkletree_size;
    signal input path[nLevels];
    signal input siblings[nLevels];
    signal input current_date[6];

    // Compute the commitment
    component poseidon_hasher = Poseidon(6);
    poseidon_hasher.inputs[0] <== secret;
    poseidon_hasher.inputs[1] <== attestation_id;
    poseidon_hasher.inputs[2] <== pubkey_leaf;
    signal mrz_packed[3] <== PackBytes(93)(mrz);
    for (var i = 0; i < 3; i++) {
        poseidon_hasher.inputs[i + 3] <== mrz_packed[i];
    }

    // Verify commitment inclusion
    signal computedRoot <== BinaryMerkleRoot(nLevels)(poseidon_hasher.out, merkletree_size, path, siblings);
    merkle_root === computedRoot;

    // Verify validity of the passport
    component isValid = IsValid();
    isValid.currDate <== current_date;
    for (var i = 0; i < 6; i++) {
        isValid.validityDateASCII[i] <== mrz[70 + i];
    }

    1 === isValid.out;
}
