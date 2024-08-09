pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/utils/bytes.circom";
include "../utils/isOlderThan.circom";
include "../utils/isValid.circom";
include "binary-merkle-root.circom";
include "../utils/validatePassport.circom";

template Disclose(nLevels) {
    signal input secret;
    signal input attestation_id;
    signal input pubkey_leaf;
    signal input mrz[93];

    signal input merkle_root;
    signal input merkletree_size;
    signal input path[nLevels];
    signal input siblings[nLevels];

    signal input bitmap[90];
    signal input scope;
    signal input current_date[6]; // YYMMDD - num
    signal input majority[2]; // YY - ASCII
    
    signal input user_identifier; // can be address for onchain usage, any user id for offchain usage

    signal output nullifier; // Poseidon(secret, scope)
    signal output revealedData_packed[3];

    // Validate Passport
    ValidatePassport(nLevels)(secret, attestation_id, pubkey_leaf, mrz, merkle_root, merkletree_size, path, siblings, current_date);

    // Disclose optional data
    component isOlderThan = IsOlderThan();
    isOlderThan.majorityASCII <== majority;
    for (var i = 0; i < 6; i++) {
        isOlderThan.currDate[i] <== current_date[i];
        isOlderThan.birthDateASCII[i] <== mrz[62 + i];
    }
    signal older_than[2];
    older_than[0] <== isOlderThan.out * majority[0];
    older_than[1] <== isOlderThan.out * majority[1];

    // constrain bitmap to be 0s or 1s
    for (var i = 0; i < 90; i++) {
        bitmap[i] * (bitmap[i] - 1) === 0;
    }

    signal revealedData[90];
    for (var i = 0; i < 88; i++) {
        revealedData[i] <== mrz[5+i] * bitmap[i];
    }
    revealedData[88] <== older_than[0] * bitmap[88];
    revealedData[89] <== older_than[1] * bitmap[89];
    revealedData_packed <== PackBytes(90)(revealedData);

    // Generate scope nullifier
    component poseidon_nullifier = Poseidon(2);

    poseidon_nullifier.inputs[0] <== secret;
    poseidon_nullifier.inputs[1] <== scope;
    nullifier <== poseidon_nullifier.out;
}

component main { public [ merkle_root, scope, user_identifier, current_date, attestation_id] } = Disclose(16);