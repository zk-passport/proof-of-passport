pragma circom 2.1.5;

// include "@zk-email/circuits/utils/bytes.circom";
// include "../../utils/Sha1BytesStatic.circom";
// include "../../utils/Sha1Bytes.circom";
// include "../../utils/rsaPkcs1.circom";
// include "dmpierre/sha1-circom/circuits/sha1.circom";
include "../../utils/circom-ecdsa/ecdsa.circom";

// n, k, max_datahashes_bytes
template PassportVerifier_ecdsaWithSHA1Encryption(n,k) {


    // signal input r[k];
    // signal input s[k];
    // signal input msghash[k];
    // signal input pubkey[2][k];

    signal r[6];
    signal s[6];
    signal msghash[6];
    signal pubkey[2][6];
    
    r[0] <== 4356595461396;
    r[1] <== 7517478021216;
    r[2] <== 461130717732;
    r[3] <== 582422961751;
    r[4] <== 4827585151075;
    r[5] <== 1832639904957;

    

    s[0] <== 491010621745;
    s[1] <== 1153769202424;
    s[2] <== 7481879050338;
    s[3] <== 2362326744248;
    s[4] <== 5715790716735;
    s[5] <== 1133501322735;


    pubkey[0][0] <== 4705934152392;
    pubkey[0][1] <== 8704141833119;
    pubkey[0][2] <== 4827796658582;
    pubkey[0][3] <== 5154602932886;
    pubkey[0][4] <== 6957561507837;
    pubkey[0][5] <== 974696539144;

    pubkey[1][0] <== 8600645394507;
    pubkey[1][1] <== 418369241838;
    pubkey[1][2] <== 1959034348828;
    pubkey[1][3] <== 6964301761725;
    pubkey[1][4] <== 1750427296885;
    pubkey[1][5] <== 1782063459524;


    msghash[0] <== 1234;
    msghash[1] <== 0;
    msghash[2] <== 0;
    msghash[3] <== 0;
    msghash[4] <== 0;
    msghash[5] <== 0;

    // component ecdsa_verify  = ECDSAVerifyNoPubkeyCheck(n,k);

    // ecdsa_verify.r <== r;
    // ecdsa_verify.s <== s;
    // ecdsa_verify.msghash <== msghash;
    // ecdsa_verify.pubkey <== pubkey;

    // log(ecdsa_verify.valid);

    // var hashLen = 20;
    // var eContentBytesLength = 72 + hashLen; // 92

    // signal input mrz[93]; // formatted mrz (5 + 88) chars
    // signal input dg1_hash_offset;
    // signal input dataHashes[max_datahashes_bytes];
    // signal input datahashes_padded_length;
    // signal input eContentBytes[eContentBytesLength];

    // // pubkey that signed the passport 
    // // for ecdsa it will be qx and qy on p256 curve need use bigInt.circom 
    // // coz p256 modulus extends 254 bit range in circom

    // signal input dsc_modulus[k];
    // // signal input dsc_public_key_x[k];
    // // signal input dsc_public_key_y[k];


    // // signature of the passport
    // signal input signature[k];

    // // compute sha1 of formatted mrz
    // signal mrzSha[160] <== Sha1BytesStatic(93)(mrz);

    // // mrzSha_bytes: list of 32 Bits2Num
    // component mrzSha_bytes[hashLen];

    // // cast the 160 bits from mrzSha into a list of 20 bytes
    // for (var i = 0; i < hashLen; i++) {
    //     mrzSha_bytes[i] = Bits2Num(8);

    //     for (var j = 0; j < 8; j++) {
    //         mrzSha_bytes[i].in[7 - j] <== mrzSha[i * 8 + j];
    //     }
    // }

    // // assert mrz_hash equals the one extracted from dataHashes input (bytes dg1_hash_offset to dg1_hash_offset + hashLen)
    // signal dg1Hash[hashLen] <== SelectSubArray(max_datahashes_bytes, hashLen)(dataHashes, dg1_hash_offset, hashLen);
    // for(var i = 0; i < hashLen; i++) {
    //     dg1Hash[i] === mrzSha_bytes[i].out;
    // }

    // // hash dataHashes dynamically
    // signal dataHashesSha[160] <== Sha1Bytes(max_datahashes_bytes)(dataHashes, datahashes_padded_length);

    // // get output of dataHashes into bytes to check against eContent
    // component dataHashesSha_bytes[hashLen];
    // for (var i = 0; i < hashLen; i++) {
    //     dataHashesSha_bytes[i] = Bits2Num(8);
    //     for (var j = 0; j < 8; j++) {
    //         dataHashesSha_bytes[i].in[7 - j] <== dataHashesSha[i * 8 + j];
    //     }
    // }

    // // assert dataHashesSha is in eContentBytes in range bytes 72 to 92
    // for(var i = 0; i < hashLen; i++) {
    //     eContentBytes[eContentBytesLength - hashLen + i] === dataHashesSha_bytes[i].out;
    // }

    // // hash eContentBytes
    // signal eContentSha[160] <== Sha1BytesStatic(eContentBytesLength)(eContentBytes);

    // // get output of eContentBytes sha1 into k chunks of n bits each
    // var msg_len = (160 + n) \ n;

    // //eContentHash: list of length 160/n +1 of components of n bits 
    // component eContentHash[msg_len];
    // for (var i = 0; i < msg_len; i++) {
    //     eContentHash[i] = Bits2Num(n);
    // }

    // for (var i = 0; i < 160; i++) {
    //     eContentHash[i \ n].in[i % n] <== eContentSha[159 - i];
    // }

    // for (var i = 160; i < n * msg_len; i++) {
    //     eContentHash[i \ n].in[i % n] <== 0;
    // }
    
    // ! 43 * 6 = 258 > circom field 254
    // ! 64 * 4 = 256 > circom field 254 we can use any of the these
        
    // rsa.modulus <== dsc_modulus;
    // rsa.signature <== signature;
    // var k  = div_ceil(10 ,3 );
}
// 121, 17, 320
component main  =  PassportVerifier_ecdsaWithSHA1Encryption(43, 6);

