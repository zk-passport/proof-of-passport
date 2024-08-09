pragma circom 2.1.5;

include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/fp.circom";
include "@zk-email/circuits/lib/bigint-func.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/sha256.circom";
include "./Mgf1Sha256.circom";
include "./xor.circom";

/// @notice Returns the encoded message in 8bit chunks.
/// @param n Number of bits per chunk the modulus is split into.
/// @param k Number of chunks the modulus is split into.
template RSASSAPSS_Decode(n, k) {
    signal input signature[k];
    signal input modulus[k];
    signal encoded[k];
    var emLen = div_ceil((n*k) -1, 8); //refer point 2.C of https://datatracker.ietf.org/doc/html/rfc8017#section-8.1.2
    signal eMsgInBits[emLen * 8];
    signal output eM[emLen]; //8 bit words

    component bigPow = FpPow65537Mod(n, k);
    for (var i = 0; i < k; i++) {
        bigPow.base[i] <== signature[i];
        bigPow.modulus[i] <== modulus[i];
    }

    encoded <== bigPow.out;

    component num2Bits[k];
    for (var i = 0; i < k; i++) {
        num2Bits[i] = Num2Bits(n);
        num2Bits[i].in <== encoded[i];

        for (var j = 0; j < n; j++) {
            if (i * n + j < emLen * 8)
                eMsgInBits[i * n + j] <== num2Bits[i].out[j];
        }
    }

    component bits2Num[emLen];
    for (var i = 0; i < emLen; i++) {
        bits2Num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            bits2Num[i].in[7-j] <== eMsgInBits[i*8 + (7-j)];
        }
        eM[i] <== bits2Num[i].out;
    }
}

/// @param emBits Length of the encoded message in bits.
/// @param messageLen Length of the message in bytes.
template RSASSAPSSVerify_SHA256(emBits, messageLen) {
    var emLen = div_ceil(emBits, 8);
    signal input eM[emLen];
    signal input message[messageLen];
    signal mHash[256];
    var hLen = 32;
    var sLen = 32;
    var hLenBits = 256; //sha256
    var sLenBits = 256; //sha256
    var emLenBits = emLen * 8;

    signal messageBits[messageLen*8];
    component num2BitsMessage[messageLen];
    for (var i = 0; i < messageLen; i++) {
        num2BitsMessage[i] = Num2Bits(8);
        num2BitsMessage[i].in <== message[i];
        for (var j = 0; j < 8; j++) {
            messageBits[i*8 +j] <== num2BitsMessage[i].out[7-j];
        }
    }

    //mHash
    component sha256 = Sha256(messageLen*8);
    sha256.in <== messageBits;
    for (var i = 0; i < 256; i++) {
        mHash[i] <== sha256.out[i];
    }

    //If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    assert(emLen >= 32 + 32 +2);

    //should end with 0xBC (188 in decimal)
    assert(eM[0] == 188); //inconsistent

    signal eMsgInBits[emLen * 8];
    signal maskedDB[(emLen - hLen - 1) * 8];
    signal hash[hLen * 8];
    var dbMaskLen = emLen - hLen - 1;
    signal dbMask[dbMaskLen * 8];
    signal DB[dbMaskLen * 8];
    signal salt[hLen * 8];

    //split eM into bits 
    component num2Bits[emLen];
    for (var i = 0; i < emLen; i++) {
        num2Bits[i] = Num2Bits(8);
        num2Bits[i].in <== eM[emLen-1-i];
        for (var j = 0; j < 8; j++) {
            eMsgInBits[(i * 8) + j] <== num2Bits[i].out[8-j-1];
        }
    }

    //extract maskedDB. leftmost emLen - hLen - 1 octets of EM
    for (var i=0; i< (emLen - hLen -1) * 8; i++) {
        maskedDB[i] <== eMsgInBits[i];
    }

    //Ref: https://github.com/directdemocracy-vote/app/blob/d0590b5515e749fa72fc50f05062273eb2465da1/httpdocs/app/js/rsa-blind.js#L183
    signal mask <== 0xff00 >> (emLenBits / 8 - emBits) & 0xff;
    signal maskBits[8];
    component num2BitsMask = Num2Bits(8);
    num2BitsMask.in <== mask;
    for (var i = 0; i < 8; i++) {
        maskBits[i] <== num2BitsMask.out[7-i];
    }
    for (var i=0; i<8; i++) {
        assert(maskBits[i] & maskedDB[i] == 0);
    }

    //extract hash
    for (var i=0; i<hLenBits; i++) {
        hash[i] <== eMsgInBits[(emLenBits) - hLenBits-8 +i];
    }

    //DbMask MGF1
    component MGF1 = Mgf1Sha256(hLen, dbMaskLen);
    for (var i = 0; i < (hLenBits); i++) {
        MGF1.seed[i] <== hash[i];
    }
    for (var i = 0; i < dbMaskLen * 8; i++) {
        dbMask[i] <== MGF1.out[i];
    }

    //DB = maskedDB xor dbMask
    component xor = Xor2(dbMaskLen * 8);
    for (var i = 0; i < dbMaskLen * 8; i++) {
        xor.a[i] <== maskedDB[i];
        xor.b[i] <== dbMask[i];
    }
    // Ref: https://github.com/directdemocracy-vote/app/blob/d0590b5515e749fa72fc50f05062273eb2465da1/httpdocs/app/js/rsa-blind.js#L188-L190
    for (var i = 0; i < dbMaskLen * 8; i++) {
        //setting the first leftmost byte to 0
        if (i==0) {
            DB[i] <== 0;
        } else {
            DB[i] <== xor.out[i];
        }
    }

    // If the emLen - hLen - sLen - 2 leftmost octets of DB are not
    // zero, output "inconsistent" and stop.
    for (var i = 0; i < (emLenBits-528); i++) { //hLenBits + sLenBits + 16 = 256 + 256 + 16 = 528
        assert(DB[i] == 0);
    }
    // if the octet at position emLen - hLen - sLen - 1 (the
    // leftmost position is "position 1") does not have hexadecimal
    // value 0x01, output "inconsistent" and stop.
    component bits2Num = Bits2Num(8);
    for (var i = 0; i < 8; i++) {
        bits2Num.in[7-i] <== DB[(emLenBits)- 528 +i]; //emLen - hLen - sLen - 1

    }
    assert(bits2Num.out == 1);

    //extract salt
    for (var i = 0; i < sLenBits; i++) {
        //last sLenBits (256) bits of DB
        salt[256 -1 - i] <== DB[(dbMaskLen * 8) -1 - i];
    }

    //M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    signal mDash[576]; // 8 + hLen + sLen = 8 + 32 + 32 = 72 bytes = 576 bits
    for (var i = 0; i < 64; i++) {
        mDash[i] <== 0;
    }
    for (var i = 0 ; i < 256; i++) {
        mDash[64 + i] <== mHash[i];
    }
    for (var i = 0; i < 256; i++) {
        mDash[320 + i] <== salt[i];
    }

    component hDash = Sha256(576);
    hDash.in <== mDash;
    for (var i = 0; i < 256; i++) {
        assert(hDash.out[i] == hash[i]);
    }
}