pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "binary-merkle-root.circom";
include "../utils/getCommonLength.circom";
include "../utils/validatePassport.circom";
include "../utils/smt.circom";

template ProveNameNotInOfac(nLevels) {
    signal input secret;
    signal input attestation_id;
    signal input pubkey_leaf;
    signal input mrz[93];
    signal input merkle_root;
    signal input merkletree_size;
    signal input path[nLevels];
    signal input siblings[nLevels];
    signal input current_date[6]; 

    signal input closest_leaf;
    signal input smt_root;
    signal input smt_siblings[256];
    signal output proofType;
    signal output proofLevel;

    // Validate passport
    ValidatePassport(nLevels)(secret, attestation_id, pubkey_leaf, mrz, merkle_root, merkletree_size, path, siblings, current_date);

    // Name Hash
    component poseidon_hasher[3];
    for (var j = 0; j < 3; j++) {
        poseidon_hasher[j] = Poseidon(13);
        for (var i = 0; i < 13; i++) {
            poseidon_hasher[j].inputs[i] <== mrz[10 + 13 * j + i];
        }
    }

    signal name_hash <== Poseidon(3)([poseidon_hasher[0].out, poseidon_hasher[1].out, poseidon_hasher[2].out]);
    signal smtleaf_hash <== Poseidon(3)([name_hash, 1,1]);

    // SMT Verification
    signal closestleaf <== SMTVerify(256)(name_hash, 1, closest_leaf, smt_root, smt_siblings);

    proofType <== IsEqual()([closestleaf,smtleaf_hash]); 
    proofType === 0;  // Uncomment this line to make circuit handle both membership and non-membership proof and returns the type of proof (0 for non-membership, 1 for membership)

    proofLevel <== 1;
    
}

component main { public [ merkle_root,smt_root ] } = ProveNameNotInOfac(16);
