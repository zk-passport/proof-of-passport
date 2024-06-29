pragma circom 2.1.5;

// include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/utils/bytes.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/utils/array.circom";
include "./utils/Sha256BytesStatic.circom";
include "./utils/RSASSAPSS.circom";


template PassportVerifier_sha256WithRSASSAPSS_65537(n, k, max_datahashes_bytes) {
    var hashLen = 32;
    var eContentBytesLength = 72 + hashLen; // 104

    signal input mrz[93]; // formatted mrz (5 + 88) chars
    signal input dg1_hash_offset;
    signal input dataHashes[max_datahashes_bytes];
    signal input datahashes_padded_length;
    signal input eContentBytes[eContentBytesLength];

    // pubkey that signed the passport
    signal input pubkey[k];

    // signature of the passport
    signal input signature[k];

    // compute sha256 of formatted mrz
    signal mrzSha[256] <== Sha256BytesStatic(93)(mrz);

    // mrzSha_bytes: list of 32 Bits2Num
    component mrzSha_bytes[hashLen];

    // cast the 256 bits from mrzSha into a list of 32 bytes
    for (var i = 0; i < hashLen; i++) {
        mrzSha_bytes[i] = Bits2Num(8);

        for (var j = 0; j < 8; j++) {
            mrzSha_bytes[i].in[7 - j] <== mrzSha[i * 8 + j];
        }
    }

    // assert mrz_hash equals the one extracted from dataHashes input (bytes dg1_hash_offset to dg1_hash_offset + hashLen)
    signal dg1Hash[hashLen] <== SelectSubArray(max_datahashes_bytes, hashLen)(dataHashes, dg1_hash_offset, hashLen);
    for(var i = 0; i < hashLen; i++) {
        dg1Hash[i] === mrzSha_bytes[i].out;
    }

    // hash dataHashes dynamically
    signal dataHashesSha[256] <== Sha256Bytes(max_datahashes_bytes)(dataHashes, datahashes_padded_length);

    // get output of dataHashes sha256 into bytes to check against eContent
    component dataHashesSha_bytes[hashLen];
    for (var i = 0; i < hashLen; i++) {
        dataHashesSha_bytes[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            dataHashesSha_bytes[i].in[7 - j] <== dataHashesSha[i * 8 + j];
        }
    }

    // assert dataHashesSha is in eContentBytes in range bytes 72 to 104
    for(var i = 0; i < hashLen; i++) {
        eContentBytes[eContentBytesLength - hashLen + i] === dataHashesSha_bytes[i].out;
    }

    // decode signature to get encoded message
    component rsaDecode = RSASSAPSS_Decode(n, k);
    rsaDecode.signature <== signature;
    rsaDecode.modulus <== pubkey;
    var emLen = div_ceil((n*k) -1, 8); //refer point 2.C of https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    signal encodedMessage[emLen] <== rsaDecode.eM;

    // verify eContent signature
    component rsaVerify = RSASSAPSSVerify_SHA256((n*k) -1 , eContentBytesLength); //point 3 from https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    rsaVerify.eM <== encodedMessage;
    rsaVerify.message <== eContentBytes;
}