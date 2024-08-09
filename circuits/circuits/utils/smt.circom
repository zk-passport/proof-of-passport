pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "binary-merkle-root.circom";
include "getCommonLength.circom";

template SMTVerify(nLength) {
    signal input key;
    signal input value;
    signal input closest_key; // key itself if checking for inclusion
    signal input root;
    signal input siblings[nLength];
    signal output closestleaf;

    // Calculate depth of the smt tree
    signal depth <== SiblingsLength()(siblings);

    // Calulate the path needed
    signal path[nLength];
    signal path_in_bits_reversed[nLength] <== Num2Bits(256)(key);
    var path_in_bits[nLength];
    
    for (var i = 0; i < nLength; i++) {
        path_in_bits[i] = path_in_bits_reversed[nLength-1-i];
    }
    
    // Shift the path to the left by depth to make it compatible for BinaryMerkleRoot function
    component ct1 = VarShiftLeft(nLength,nLength);
    ct1.in <== path_in_bits;
    ct1.shift <== (nLength-depth);
    path <== ct1.out; 

    // Closest_key to Closest_leaf
    signal closest_hash <== Poseidon(3)([closest_key, value,1]);  
    signal isClosestZero <== IsEqual()([closest_key,0]);
    signal closest <== IsEqual()([isClosestZero,0]); // Because zk-kit/smt stores a 0 leaf as itself and not as Hash(0,value,1)
    closestleaf <== closest_hash * closest;

    // Verification
    signal computedRoot <== BinaryMerkleRoot(nLength)(closestleaf, depth, path, siblings);
    computedRoot === root;

}
