import { LeanIMT } from '@zk-kit/lean-imt';
import { sha256 } from 'js-sha256';
import { sha1 } from 'js-sha1';
import { sha384 } from 'js-sha512';

export function formatMrz(mrz: string) {
  const mrzCharcodes = [...mrz].map(char => char.charCodeAt(0));

  mrzCharcodes.unshift(88); // the length of the mrz data
  mrzCharcodes.unshift(95, 31); // the MRZ_INFO_TAG
  mrzCharcodes.unshift(91); // the new length of the whole array
  mrzCharcodes.unshift(97); // the tag for DG1

  return mrzCharcodes;
}

export function parsePubKeyString(pubKeyString: string) {
  const modulusMatch = pubKeyString.match(/modulus: ([\w\d]+)\s*public/);
  const publicExponentMatch = pubKeyString.match(/public exponent: (\w+)/);

  const modulus = modulusMatch ? modulusMatch[1] : null;
  const exponent = publicExponentMatch ? publicExponentMatch[1] : null;

  if (!modulus || !exponent) {
    throw new Error('Could not parse public key string');
  }

  return {
    modulus,
    exponent,
  };
}

export function formatAndConcatenateDataHashes(
  dataHashes: [number, number[]][],
  hashLen: number,
  dg1HashOffset: number
) {
  // concatenating dataHashes :
  let concat: number[] = []

  const startingSequence = Array.from({length: dg1HashOffset},
    () => Math.floor(Math.random() * 256) - 128
  );

  // sha256 with rsa (index of mrzhash is 31)
  // const startingSequence = [
  //   // SEQUENCE + long form indicator + length (293 bytes)
  //   48, -126, 1, 37,
  //   // length: 1 byte
  //   2, 1,
  //   // LDSSecurityObjectVersion v0
  //   0,
  //   // padding: size 11 - size 9...
  //   48, 11, 6, 9,
  //   // 2.16.840.1.101.3.4.2.1 is sha256
  //   96, -122, 72, 1, 101, 3, 4, 2, 1,
  //   // SEQUENCE + long form indicator + length (273 bytes)
  //   48, -126, 1, 17,
  // ]

  // rsassaPss (index of mrzhash is 30)
  // // SEQUENCE + short form indicator + length (137 bytes)
  // 48, -127, -119,
  // 2, 1,
  // 0,
  // 48, 13, 6, 9,
  // // 2.16.840.1.101.3.4.2.1 is sha256
  // 96, -122, 72, 1, 101, 3, 4, 2, 1,
  // // NULL tag + SEQUENCE + length (117 bytes)
  // 5, 0, 48, 117,
  
  // SHA384withECDSA (index of mrzhash is 33)
  // // SEQUENCE + long form indicator + length (313 bytes)
  // 48, -126, 1, 57,
  // 2, 1,
  // 1,
  // 48, 13, 6, 9,
  // // 2.16.840.1.101.3.4.2.1 is sha384
  // 96, -122, 72, 1, 101, 3, 4, 2, 2,
  // // NULL tag + SEQUENCE + long form indicator + length (275 bytes)
  // 5, 0, 48, -126, 1, 19,

  // => current conclusion is we should be able to just hardcode indexes
  // => as they shouldn't change must for same sig alg.
  // => wrong: our rsassaPss has less datagroups so the length is different (30 rather then 31)

  // console.log(`startingSequence`, startingSequence.map(byte => (byte < 0 ? byte + 256 : byte).toString(16).padStart(2, '0')).join(''));

  concat.push(...startingSequence)

  for (const dataHash of dataHashes) {
    // console.log(`dataHash ${dataHash[0]}`, dataHash[1].map(byte => (byte < 0 ? byte + 256 : byte).toString(16).padStart(2, '0')).join(''));

    concat.push(...dataHash[1])
    // concat.push(...[48, hashLen + 5, 2, 1, dataHash[0], 4, hashLen, ...dataHash[1]])
    // 48, 37, 2, 1, 1, 4, 32,
    // 48, 53, 2, 1, 1, 4, 48,
  }

  return concat;
}

export function assembleEContent(
  messageDigest: number[],
) {
  const constructedEContent = [];

  // Detailed description is in private file r&d.ts for now
  // First, the tag and length, assumed to be always the same
  constructedEContent.push(...[49, 102]);

  // 1.2.840.113549.1.9.3 is RFC_3369_CONTENT_TYPE_OID
  constructedEContent.push(
    ...[48, 21, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 3],
  );
  // 2.23.136.1.1.1 is ldsSecurityObject
  constructedEContent.push(...[49, 8, 6, 6, 103, -127, 8, 1, 1, 1]);

  // 1.2.840.113549.1.9.5 is signing-time
  constructedEContent.push(
    ...[48, 28, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 5],
  );
  // mock time of signature
  constructedEContent.push(...[49, 15, 23, 13, 49, 57, 49, 50, 49, 54, 49, 55, 50, 50, 51, 56, 90]);
  // 1.2.840.113549.1.9.4 is RFC_3369_MESSAGE_DIGEST_OID
  constructedEContent.push(
    ...[48, 47, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 4],
  );
  // TAG and length of the message digest
  constructedEContent.push(...[49, 34, 4, 32]);

  constructedEContent.push(...messageDigest);
  return constructedEContent;
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
export function hash(signatureAlgorithm: string, bytesArray: number[]) {
  const unsignedBytesArray = bytesArray.map(toUnsignedByte);
  const hash = (signatureAlgorithm == 'sha1WithRSAEncryption')
    ? sha1(unsignedBytesArray)
    : (signatureAlgorithm == 'SHA384withECDSA')
    ? sha384(unsignedBytesArray)
    : (signatureAlgorithm == 'sha256WithRSAEncryption' || signatureAlgorithm == 'sha256WithRSASSAPSS')
    ? sha256(unsignedBytesArray)
    : sha256(unsignedBytesArray); // defaults to sha256
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

export function formatSigAlgNameForCircuit(
  sigAlg: string,
  exponent?: string
) {
  // replace - by _, for instance for ecdsa-with-SHA256
  sigAlg = sigAlg.replace(/-/g, '_')
  // add exponent, for instance for sha256WithRSAEncryption
  return exponent ? `${sigAlg}_${exponent}` : sigAlg
}

export function bigIntToChunkedBytes(num: BigInt | bigint, bytesPerChunk: number, numChunks: number) {
  const res: string[] = [];
  const bigintNum: bigint = typeof num == "bigint" ? num : num.valueOf();
  const msk = (1n << BigInt(bytesPerChunk)) - 1n;
  for (let i = 0; i < numChunks; ++i) {
    res.push(((bigintNum >> BigInt(i * bytesPerChunk)) & msk).toString());
  }
  return res;
}

export function hexStringToSignedIntArray(hexString: string) {
  let result = [];
  for (let i = 0; i < hexString.length; i += 2) {
    let byte = parseInt(hexString.substr(i, 2), 16);
    result.push(byte > 127 ? byte - 256 : byte);
  }
  return result;
};

export function formatRoot(root: string): string {
  let rootHex = BigInt(root).toString(16);
  return rootHex.length % 2 === 0 ? "0x" + rootHex : "0x0" + rootHex;
}

export function getCurrentDateYYMMDD(dayDiff: number = 0): number[] {
  const date = new Date();
  date.setDate(date.getDate() + dayDiff); // Adjust the date by the dayDiff
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();
  const YY = (`0${year % 100}`).slice(-2);
  const MM = (`0${month}`).slice(-2);
  const DD = (`0${day}`).slice(-2);

  const yymmdd = `${YY}${MM}${DD}`;
  return Array.from(yymmdd).map(char => parseInt(char));
}

export function getHashLen(signatureAlgorithm: string) {
  switch (signatureAlgorithm) {
    case "sha1WithRSAEncryption":
    case "ecdsa-with-SHA1":
      return 20;
    case "sha256WithRSAEncryption":
    case "rsassaPss":
    case "ecdsa-with-SHA256":
      return 32;
    case "sha384WithRSAEncryption":
    case "ecdsa-with-SHA384":
      return 48;
    case "sha512WithRSAEncryption":
    case "ecdsa-with-SHA512":
      return 64;
    default:
      console.log(`${signatureAlgorithm} not found in getHashLen`);
      return 32;
  }
}

export function packBytes(unpacked) {
  const bytesCount = [31, 31, 31];
  let packed = [0n, 0n, 0n];

  let byteIndex = 0;
  for (let i = 0; i < bytesCount.length; i++) {
    for (let j = 0; j < bytesCount[i]; j++) {
      if (byteIndex < unpacked.length) {
        packed[i] |= BigInt(unpacked[byteIndex]) << (BigInt(j) * 8n);
      }
      byteIndex++;
    }
  }
  return packed;
}


export function generateMerkleProof(imt: LeanIMT, _index: number, maxDepth: number) {
  const { siblings: merkleProofSiblings, index } = imt.generateProof(_index)
  const depthForThisOne = merkleProofSiblings.length
  // The index must be converted to a list of indices, 1 for each tree level.
  // The circuit tree depth is 20, so the number of siblings must be 20, even if
  // the tree depth is actually 3. The missing siblings can be set to 0, as they
  // won't be used to calculate the root in the circuit.
  const merkleProofIndices: number[] = []

  for (let i = 0; i < maxDepth; i += 1) {
    merkleProofIndices.push((index >> i) & 1)
    if (merkleProofSiblings[i] === undefined) {
      merkleProofSiblings[i] = BigInt(0)
    }
  }
  return { merkleProofSiblings, merkleProofIndices, depthForThisOne  }
}

export function findSubarrayIndex(arr: any[], subarray: any[]): number {
  return arr.findIndex((_, index) =>
    subarray.every((element, i) => element === arr[index + i])
  );
}

export function stringToAsciiBigIntArray(str: string): BigInt[] {
  let asciiBigIntArray = [];
  for (let i = 0; i < str.length; i++) {
      asciiBigIntArray.push(BigInt(str.charCodeAt(i)));
  }
  return asciiBigIntArray;
}