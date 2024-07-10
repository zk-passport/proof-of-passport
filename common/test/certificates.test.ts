import { assert, expect } from 'chai'
import path from "path";
import { readCertificate, getPublicKey, extractModulus } from "../src/utils/certificates";

describe("Certificates (sha256_rsa_2048)", function () {
    const cert = readCertificate("src/mock_certificates/sha256_rsa_2048/mock_csca.crt");

    it("should get public key from certificate", async function () {
        const publicKey = getPublicKey(cert);
        expect(publicKey.type, "should be RSA").to.equal("RSA");
        expect(publicKey.n.bitLength(), "should be 2048").to.equal(2048);
        expect(publicKey.e.toString(), "should be 65537").to.equal("65537");
    });

    it("should extract modulus from certificate", async function () {
        const publicKeyInfo = cert.getPublicKeyHex();
        const modulus = extractModulus(publicKeyInfo);
        expect(modulus, "should not be null").to.not.be.null;
        expect(modulus.length, "should be 512").to.equal(260);
        expect(modulus, "should be equal").to.equal(
            "010100ab5919e1a521f03ef9fae6752e2ee18b4f860638e229fe7e0db738bf0ebd31b30599462d" + 
            "84df307a0eb300aeda7db9a9029738cc867e52cb68d72c4a9da9171b5a5847a6e228a0bf128ba7" +
            "32d28fd2bbdb8c8df59c7b053fb73c2203762f58a43ee1dcf034b6156b255c3a37d90f7ead439f" +
            "532a2fa49591c4e08d8b53db34");
    });
});

describe("Certificates (sha1_rsa_2048)", function () {
    const cert = readCertificate("src/mock_certificates/sha1_rsa_2048/mock_csca.crt");

    it("should get public key from certificate", async function () {
        const publicKey = getPublicKey(cert);
        expect(publicKey.type, "should be RSA").to.equal("RSA");
        expect(publicKey.n.bitLength(), "should be 2048").to.equal(2048);
        expect(publicKey.e.toString(), "should be 65537").to.equal("65537");
    });

    it("should extract modulus from certificate", async function () {
        const publicKeyInfo = cert.getPublicKeyHex();
        const modulus = extractModulus(publicKeyInfo);
        expect(modulus, "should not be null").to.not.be.null;
        expect(modulus.length, "should be 512").to.equal(260);
        expect(modulus, "should be equal").to.equal(
            "010100993920f4bccf753b0580e2fab971c218cca5be8e375c3e41a5d20e3799c115fc7eb4ac42d" +
            "f4007e352406c905bf240d8d455d03df984eb744e7d4d16f68321f2fbbf9fec82276d85e31aa038" +
            "0d35d9c5f0984c1ae80f1dc5e3aac6ff7674176d3795e97049dee45235ab3082091a2843994c1a2" +
            "92218988f55f5db2053e054");
    });
});
