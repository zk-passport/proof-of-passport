pragma circom 2.1.5;

include "../../utils/RSASSAPSS.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";

template RSASSAPSS_tester_2048(n, k) {
    var eContentBytesLength = 104;

    signal input signature[k];
    signal input pubkey[k];
    signal input eContentBytes[eContentBytesLength];
    
    component rsaDecode = RSASSAPSS_Decode(n, k);
    rsaDecode.signature <== signature;
    rsaDecode.modulus <== pubkey;
    var encoded_message_len = div_ceil((n*k) -1, 8);
    signal encodedMessage[encoded_message_len] <== rsaDecode.eM;

    component rsaVerify = RSASSAPSSVerify_SHA256((n*k) -1, eContentBytesLength);
    rsaVerify.eM <== encodedMessage;
    rsaVerify.message <== eContentBytes;
}

component main = RSASSAPSS_tester_2048(64, 32);
