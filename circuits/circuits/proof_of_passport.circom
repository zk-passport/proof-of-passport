pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./helpers/extract.circom";
include "./passport_verifier.circom";
include "./merkle_tree/tree.circom";

template ProofOfPassport(n, k, nLevels, pubkeySize) {
    signal input mrz[93]; // formatted mrz (5 + 88) chars
    signal input dataHashes[297];
    signal input eContentBytes[104];
    signal input signature[k];

    signal input signatureAlgorithm;
    signal input pubkey[pubkeySize];

    signal input pathIndices[nLevels];
    signal input siblings[nLevels];
    signal input root;

    signal input reveal_bitmap[88];
    signal input address;

    // Converting pub_key (modulus) into 11 chunks of 192 bits, assuming original n, k are 64 and 32.
    // This is because Poseidon circuit only supports an array of 16 elements.
    var k3_chunked_size = 11;  // Since ceil(32 / 3) in integer division is 11
    signal pubkey_hash_input[k3_chunked_size];
    for(var i = 0; i < k3_chunked_size; i++) {
        if(i == k3_chunked_size - 1) {
            if(k % 3 == 1) {
                pubkey_hash_input[i] <== pubkey[3*i];
            } else if(k % 3 == 2) {
                pubkey_hash_input[i] <== pubkey[3*i] + (1<<n) * pubkey[3*i + 1];
            } else {
                pubkey_hash_input[i] <== pubkey[3*i] + (1<<n) * pubkey[3*i + 1] + (1<<(2*n)) * pubkey[3*i + 2];
            }
        } else {
            pubkey_hash_input[i] <== pubkey[3*i] + (1<<n) * pubkey[3*i + 1] + (1<<(2*n)) * pubkey[3*i + 2];
        }
    }

    // leaf is poseidon(signatureAlgorithm, pubkey[pubkeySize])
    signal leaf_hash_input[1 + k3_chunked_size];
    leaf_hash_input[0] <== signatureAlgorithm;
    for (var i = 0; i < k3_chunked_size; i++) {
        leaf_hash_input[i+1] <== pubkey_hash_input[i];
    }
    signal leaf <== Poseidon(1 + k3_chunked_size)(leaf_hash_input);
    // log("Leaf in circuit:", leaf);

    // Verify inclusion in merkle tree
    signal computedRoot <== MerkleTreeInclusionProof(nLevels)(leaf, pathIndices, siblings);
    root === computedRoot;

    // sha256WithRSAEncryption_65537 is the only sigAlg supported right now
    signatureAlgorithm === 1;
    pubkeySize === k;


    // Verify passport
    component PV = PassportVerifier(n, k);
    PV.mrz <== mrz;
    PV.dataHashes <== dataHashes;
    PV.eContentBytes <== eContentBytes;
    PV.pubkey <== pubkey;
    PV.signature <== signature;

    // reveal reveal_bitmap bits of MRZ
    signal reveal[88];
    for (var i = 0; i < 88; i++) {
        reveal[i] <== mrz[5+i] * reveal_bitmap[i];
    }
    signal output reveal_packed[3] <== PackBytes(88, 3, 31)(reveal);

    // make nullifier public;
    // we take nullifier = signature[0, 1] which it 64 + 64 bits long, so chance of collision is 2^128
    signal output nullifier <== signature[0] * 2**64 + signature[1];
}

component main { public [ address, root ] } = ProofOfPassport(64, 32, 16, 32);

// Us:
// 1 + 3 + 1 + 1
// nullifier + reveal_packed + address + root

// Them:
// 1 + 3 + 1
// pubkey_hash + reveal_twitter_packed + address




