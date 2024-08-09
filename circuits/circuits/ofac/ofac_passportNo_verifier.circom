pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "binary-merkle-root.circom";
include "../utils/getCommonLength.circom";
include "../utils/validatePassport.circom";
include "../utils/smt.circom";

template ProvePassportNotInOfac(nLevels) {
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
    signal output proofLevel;

    // Validate passport
    ValidatePassport(nLevels)(secret, attestation_id, pubkey_leaf, mrz, merkle_root, merkletree_size, path, siblings, current_date);

    // PassportNo Hash
    component poseidon_hasher = Poseidon(9);
    for (var i = 0; i < 9; i++) {
        poseidon_hasher.inputs[i] <== mrz[49 + i];
    } 
    signal smtleaf_hash <== Poseidon(3)([poseidon_hasher.out, 1,1]);

    // SMT Verification
    signal closestleaf <== SMTVerify(256)(poseidon_hasher.out, 1, closest_leaf, smt_root, smt_siblings);

    // If leaf given = leaf calulated ; then membership proof
    signal proofType <== IsEqual()([closestleaf,smtleaf_hash]); // 1 for membership proof, 0 for non-membership proof
    proofType === 0;  // Uncomment this line to make circuit handle both membership and non-membership proof (0 for non-membership, 1 for membership)

    proofLevel <== 3;
}

component main { public [ merkle_root,smt_root ] } = ProvePassportNotInOfac(16);
