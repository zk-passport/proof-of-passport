import {sha256} from 'js-sha256';
import { LDSSecurityObject, DataGroupHash, LDSSecurityObjectVersion, DataGroupNumber, LdsSecurityObjectIdentifier, id_ldsSecurityObject, AttributeSet } from './asn1';
import { AsnSerializer, AsnConvert, AsnOctetStringConverter } from "@peculiar/asn1-schema";
import { DigestAlgorithmIdentifier, Attribute, SigningTime } from "@peculiar/asn1-cms";

export function formatMrz(mrz: string) {
  const mrzCharcodes = [...mrz].map(char => char.charCodeAt(0));

  // console.log('mrzCharcodes:', mrzCharcodes);

  mrzCharcodes.unshift(88); // the length of the mrz data
  mrzCharcodes.unshift(95, 31); // the MRZ_INFO_TAG
  mrzCharcodes.unshift(91); // the new length of the whole array
  mrzCharcodes.unshift(97); // the tag for DG1

  // console.log('mrzCharcodes with tags:', mrzCharcodes);

  return mrzCharcodes;
}

export function parsePubKeyString(pubKeyString: string) {
  const modulusMatch = pubKeyString.match(/modulus: ([\w\d]+)\s*public/);
  const publicExponentMatch = pubKeyString.match(/public exponent: (\w+)/);

  const modulus = modulusMatch ? modulusMatch[1] : null;
  const exponent = publicExponentMatch ? publicExponentMatch[1] : null;

  // console.log('Modulus:', modulus);
  // console.log('Public Exponent:', exponent);

  if (!modulus || !exponent) {
    throw new Error('Could not parse public key string');
  }

  return {
    modulus,
    exponent,
  };
}

export function formatAndConcatenateDataHashes(
  mrzHash: number[],
  dataHashes: [number, number[]][],
) {
  // Let's replace the first array with the MRZ hash
  dataHashes.shift();
  dataHashes.unshift([1, mrzHash]);

  const ldsSecurityObject = new LDSSecurityObject();
  ldsSecurityObject.version = LDSSecurityObjectVersion.v0;
  ldsSecurityObject.hashAlgorithm = new DigestAlgorithmIdentifier({
    algorithm: "1.2.840.113549.1.1.11"
  })

  for(const dataHash of dataHashes) {
    const d = new DataGroupHash();
    d.dataGroupNumber = dataHash[0];
    d.dataGroupHashValue = new Uint8Array(dataHash[1]).buffer;
    ldsSecurityObject.dataGroupHashValues.push(d);
  }

  const s = Buffer.from(AsnSerializer.serialize(ldsSecurityObject)).toString("hex");
  return hexToSignedBytes(s);
}

export function assembleEContent(
  messageDigest: number[]
) {

  const contentType = new Attribute({
    attrType : '1.2.840.113549.1.9.3', // id_contentType
    attrValues : [
      AsnConvert.serialize(new LdsSecurityObjectIdentifier(id_ldsSecurityObject))
    ]
  })

  const signingTime = new Attribute({
    attrType : '1.2.840.113549.1.9.5', // id_signingTime
    attrValues: [
        AsnConvert.serialize(new SigningTime(new Date()))
      ]
  })

  const _messageDigest = new Attribute({
    attrType : '1.2.840.113549.1.9.4', // id_messageDigest
    attrValues : [
      AsnConvert.serialize(AsnOctetStringConverter.toASN(new Uint8Array(messageDigest)))
    ]
  })

  const mySignedAttributes = new AttributeSet();
  mySignedAttributes.push(contentType);
  mySignedAttributes.push(signingTime);
  mySignedAttributes.push(_messageDigest);

  const s = Buffer.from(AsnSerializer.serialize(mySignedAttributes)).toString("hex");
  return hexToSignedBytes(s);
}

function toHexString(byteArray : number[]) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

export function toUnsigned(byte: number) {
  return byte & 0xff;
}

export function arraysAreEqual(array1: number[], array2: number[]) {
  return (
    array1.length === array2.length &&
    array1.every((value, index) => value === array2[index])
  );
}

export function toSigned(byte: number) {
  return byte > 127 ? byte - 256 : byte;
}

export const toBinaryString = (byte: any) => {
  const binary = (parseInt(byte, 10) & 0xFF).toString(2).padStart(8, '0');
  return binary;
};

export function splitToWords(
  number: bigint,
  wordsize: bigint,
  numberElement: bigint
) {
  let t = number
  const words: string[] = []
  for (let i = BigInt(0); i < numberElement; ++i) {
    const baseTwo = BigInt(2)

    words.push(`${t % BigInt(Math.pow(Number(baseTwo), Number(wordsize)))}`)
    t = BigInt(t / BigInt(Math.pow(Number(BigInt(2)), Number(wordsize))))
  }
  if (!(t == BigInt(0))) {
    throw `Number ${number} does not fit in ${(
      wordsize * numberElement
    ).toString()} bits`
  }
  return words
}

export function bytesToBigDecimal(arr: number[]): string {
  let result = BigInt(0);
  for (let i = 0; i < arr.length; i++) {
    result = result * BigInt(256) + BigInt(arr[i] & 0xff);
  }
  return result.toString();
}

export function hexToDecimal(hex: string): string {
  return BigInt(`0x${hex}`).toString();
}

// hash logic here because the one in utils.ts only works with node
export function hash(bytesArray: number[]) {
  let unsignedBytesArray = bytesArray.map(toUnsignedByte);
  let hash = sha256(unsignedBytesArray);
  return hexToSignedBytes(hash);
}

export function hexToSignedBytes(hexString: string): number[] {
  let bytes = [];
  for (let i = 0; i < hexString.length - 1; i += 2) {
    let byte = parseInt(hexString.substr(i, 2), 16);
    bytes.push(byte >= 128 ? byte - 256 : byte);
  }
  return bytes;
}

export function toUnsignedByte(signedByte: number) {
  return signedByte < 0 ? signedByte + 256 : signedByte;
}

export function hexStringToSignedIntArray(hexString: string) {
  let result = [];
  for (let i = 0; i < hexString.length; i += 2) {
    let byte = parseInt(hexString.substr(i, 2), 16);
    result.push(byte > 127 ? byte - 256 : byte);
  }
  return result;
};

function bytesToBigInt(bytes: number[]) {
  let hex = bytes.reverse().map(byte => byte.toString(16).padStart(2, '0')).join('');
  // console.log('hex', hex)
  return BigInt(`0x${hex}`).toString();
}

function splitInto(arr: number[], size: number) {
  const res = [];
  for(let i = 0; i < arr.length; i += size) {
    res.push(arr.slice(i, i + size));
  }
  return res;
}

function setFirstBitOfLastByteToZero(bytes: number[]) {
  bytes[bytes.length - 1] &= 0x7F; // AND with 01111111 to set the first bit of the last byte to 0
  return bytes;
}

// from reverse engineering ark-serialize.
export function formatProofIOS(proof: number[]) {
  const splittedProof = splitInto(proof, 32);
  splittedProof[1] = setFirstBitOfLastByteToZero(splittedProof[1]);
  splittedProof[5] = setFirstBitOfLastByteToZero(splittedProof[5]); // We might need to do the same for input 3
  splittedProof[7] = setFirstBitOfLastByteToZero(splittedProof[7]);
  const proooof = splittedProof.map(bytesToBigInt);

  return {
    "a": [proooof[0], proooof[1]],
    "b": [
      [proooof[2], proooof[3]],
      [proooof[4], proooof[5]]
    ],
    "c": [proooof[6], proooof[7]]
  }
}

export function formatInputsIOS(inputs: number[]) {
  const splitted = splitInto(inputs.slice(8), 32);
  return splitted.map(bytesToBigInt);
}