pragma circom 2.1.5;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// Computes the first n common bits of the hashes
template CommonBitsLengthFromEnd() {

    signal input bits1[256];
    signal input bits2[256];
    signal output out;

    component iseq[256];
    signal pop[256];

    pop[255] <== IsEqual()([bits1[255], bits2[255]]);

    for (var i = 254; i >= 0; i--) {
        var temp = bits2[i] - bits1[i];
        iseq[i] = IsEqual();
        bits1[i] ==> iseq[i].in[0];
        bits2[i] ==> iseq[i].in[1];
        pop[i] <== iseq[i].out*pop[i+1]; 
    }   

    var added = 0;
    for(var i = 0; i<256;i++){
        added += pop[i];
    }

    added ==> out;

}

// Computes length of an array when array is padded with 0;s from end and the last element after which padding starts is not 0, 0's might come in between.
template SiblingsLength() {
    signal input siblings[256];
    signal output length;

    // Siblings can be like (1,2,3,0,0,4,5,0,0...all 0 till 256[the padded 0 ones])
    // We need to get the length , i.e 7 in this case
    var foo[256];
    for(var i = 0; i<256; i++){
        foo[i] = 0;
    }
    foo[255] = siblings[255];
    for(var i = 256-2; i>=0; i--){
        foo[i] = siblings[i] + foo[i+1];
    }

    // convert to (15,14,12,9,9,9,5,0,0,0..), this takes out the middle 0's 
    var total = 0;
    signal pop[256];
    component iszero[256];

    for(var i = 0; i<256; i++){
        iszero[i] = IsZero();
        foo[i] ==> iszero[i].in;
        pop[i] <== iszero[i].out;
    }

    for(var i = 0; i<256; i++){
        total += pop[i];
    }
    
    256-total ==> length;
}