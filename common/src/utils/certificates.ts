import * as path from 'path';
import jsrsasign from 'jsrsasign';
import * as asn1 from 'asn1.js';
import fs from 'fs';


export const RSAPublicKey = asn1.define('RSAPublicKey', function () {
    this.seq().obj(
        this.key('n').int(),
        this.key('e').int()
    );
});

export function isRsaPublicKey(key) {
    return key.type === 'RSA' || key.type === 'RSA-PSS';
}

export function getPublicKey(certificate) {
    const publicKeyInfo = certificate.getPublicKeyHex();

    try {
        // Try to parse the public key as ASN.1
        const publicKeyAsn1 = asn1.define('PublicKey', function () {
            this.seq().obj(
                this.key('algorithm').seq().obj(
                    this.key('algorithmId').objid(),
                    this.key('parameters').optional().any()
                ),
                this.key('publicKey').bitstr()
            );
        });

        const parsed = publicKeyAsn1.decode(Buffer.from(publicKeyInfo, 'hex'), 'der');
        const publicKeyBuffer = parsed.publicKey.data;

        // Parse the RSA public key
        const rsaPublicKey = RSAPublicKey.decode(publicKeyBuffer, 'der');

        return {
            n: new jsrsasign.BigInteger(rsaPublicKey.n.toString('hex'), 16),
            e: new jsrsasign.BigInteger(rsaPublicKey.e.toString('hex'), 16),
            type: 'RSA'
        };
    } catch (e) {
        console.error("Error parsing public key:", e);
    }

    // If parsing fails, fall back to manual extraction
    const modulus = extractModulus(publicKeyInfo);
    if (modulus) {
        return { n: new jsrsasign.BigInteger(modulus, 16), type: 'RSA' };
    }

    throw new Error("Unable to extract public key");
}

export function extractModulus(publicKeyInfo: string): string | null {
    // RSA OID
    const rsaOid = '2a864886f70d010101';
    // RSA-PSS OID
    const rsaPssOid = '2a864886f70d01010a';

    let offset = publicKeyInfo.indexOf(rsaOid);
    if (offset === -1) {
        offset = publicKeyInfo.indexOf(rsaPssOid);
    }

    if (offset === -1) {
        return null;
    }

    // Skip OID and move to the bit string
    offset = publicKeyInfo.indexOf('03', offset);
    if (offset === -1) {
        return null;
    }

    // Skip bit string tag and length
    offset += 4;

    // Extract modulus
    const modulusStart = publicKeyInfo.indexOf('02', offset) + 2;
    const modulusLength = parseInt(publicKeyInfo.substr(modulusStart, 2), 16) * 2;
    const modulus = publicKeyInfo.substr(modulusStart + 2, modulusLength);

    return modulus;
}

export function readCertificate(filePath: string): jsrsasign.X509 {
    const certPem = fs.readFileSync(filePath, 'utf8');
    const certificate = new jsrsasign.X509();
    certificate.readCertPEM(certPem);
    return certificate;
}