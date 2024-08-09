import { LeanIMT } from '@zk-kit/lean-imt';
import { sha256 } from 'js-sha256';
import { sha1 } from 'js-sha1';
import { sha384 } from 'js-sha512';
import { SMT } from '@ashpect/smt';
import forge from 'node-forge';

export function formatMrz(mrz: string) {
  const mrzCharcodes = [...mrz].map((char) => char.charCodeAt(0));

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
  let concat: number[] = [];

  const startingSequence = Array.from(
    { length: dg1HashOffset },
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

  // spain
  // 48, -127,  -79,
  // 2,    1, 
  // 0,  
  // 48,    7,   6,   5, 
  // 1.3.14.3.2.26 is sha1
  // 43,  14, 3,    2,   26,
  // SEQUENCE + ...
  // 48, -127, -94, 

  // => current conclusion is we should be able to just hardcode indexes
  // => as they shouldn't change must for same sig alg.
  // => wrong: our rsassaPss has less datagroups so the length is different (30 rather then 31)

  // console.log(`startingSequence`, startingSequence.map(byte => (byte < 0 ? byte + 256 : byte).toString(16).padStart(2, '0')).join(''));

  concat.push(...startingSequence);

  for (const dataHash of dataHashes) {
    // console.log(`dataHash ${dataHash[0]}`, dataHash[1].map(byte => (byte < 0 ? byte + 256 : byte).toString(16).padStart(2, '0')).join(''));

    concat.push(...dataHash[1]);
    // concat.push(...[48, hashLen + 5, 2, 1, dataHash[0], 4, hashLen, ...dataHash[1]])
    // 48, 37, 2, 1, 1, 4, 32,
    // 48, 53, 2, 1, 1, 4, 48,
  }

  return concat;
}

export function assembleEContent(messageDigest: number[]) {
  const constructedEContent = [];

  // Detailed description is in private file r&d.ts for now
  // First, the tag and length, assumed to be always the same
  constructedEContent.push(...[49, 102]);

  // 1.2.840.113549.1.9.3 is RFC_3369_CONTENT_TYPE_OID
  constructedEContent.push(...[48, 21, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 3]);
  // 2.23.136.1.1.1 is ldsSecurityObject
  constructedEContent.push(...[49, 8, 6, 6, 103, -127, 8, 1, 1, 1]);

  // 1.2.840.113549.1.9.5 is signing-time
  constructedEContent.push(...[48, 28, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 5]);
  // mock time of signature
  constructedEContent.push(...[49, 15, 23, 13, 49, 57, 49, 50, 49, 54, 49, 55, 50, 50, 51, 56, 90]);
  // 1.2.840.113549.1.9.4 is RFC_3369_MESSAGE_DIGEST_OID
  constructedEContent.push(...[48, 47, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 4]);
  // TAG and length of the message digest
  constructedEContent.push(...[49, 34, 4, 32]);

  constructedEContent.push(...messageDigest);
  return constructedEContent;
}

export function toUnsigned(byte: number) {
  return byte & 0xff;
}

export function arraysAreEqual(array1: number[], array2: number[]) {
  return array1.length === array2.length && array1.every((value, index) => value === array2[index]);
}

export function toSigned(byte: number) {
  return byte > 127 ? byte - 256 : byte;
}

export const toBinaryString = (byte: any) => {
  const binary = (parseInt(byte, 10) & 0xff).toString(2).padStart(8, '0');
  return binary;
};

export function splitToWords(number: bigint, wordsize: bigint, numberElement: bigint) {
  let t = number;
  const words: string[] = [];
  for (let i = BigInt(0); i < numberElement; ++i) {
    const baseTwo = BigInt(2);

    words.push(`${t % BigInt(Math.pow(Number(baseTwo), Number(wordsize)))}`);
    t = BigInt(t / BigInt(Math.pow(Number(BigInt(2)), Number(wordsize))));
  }
  if (!(t == BigInt(0))) {
    throw `Number ${number} does not fit in ${(wordsize * numberElement).toString()} bits`;
  }
  return words;
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

export function hash(signatureAlgorithm: string, bytesArray: number[]): number[] {
  const unsignedBytesArray = bytesArray.map((byte) => byte & 0xff);
  let hashResult: string;

  switch (signatureAlgorithm) {
    case 'sha1WithRSAEncryption':
      hashResult = sha1(unsignedBytesArray);
      break;
    case 'SHA384withECDSA':
      hashResult = sha384(unsignedBytesArray);
      break;
    case 'sha256WithRSAEncryption':
      hashResult = sha256(unsignedBytesArray);
      break;
    case 'sha256WithRSASSAPSS':
      hashResult = sha256(unsignedBytesArray);
      break;
    case 'ecdsa-with-SHA1':
      hashResult = sha1(unsignedBytesArray);
      break;
    default:
      hashResult = sha256(unsignedBytesArray); // Default to sha256
  }
  return hexToSignedBytes(hashResult);
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

export function formatSigAlgNameForCircuit(sigAlg: string, exponent?: string) {
  // replace - by _, for instance for ecdsa-with-SHA256
  sigAlg = sigAlg.replace(/-/g, '_');
  // add exponent, for instance for sha256WithRSAEncryption
  return exponent ? `${sigAlg}_${exponent}` : sigAlg;
}

export function bigIntToChunkedBytes(
  num: BigInt | bigint,
  bytesPerChunk: number,
  numChunks: number
) {
  const res: string[] = [];
  const bigintNum: bigint = typeof num == 'bigint' ? num : num.valueOf();
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
}

export function formatRoot(root: string): string {
  let rootHex = BigInt(root).toString(16);
  return rootHex.length % 2 === 0 ? '0x' + rootHex : '0x0' + rootHex;
}

export function getCurrentDateYYMMDD(dayDiff: number = 0): number[] {
  const date = new Date();
  date.setDate(date.getDate() + dayDiff); // Adjust the date by the dayDiff
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();
  const YY = `0${year % 100}`.slice(-2);
  const MM = `0${month}`.slice(-2);
  const DD = `0${day}`.slice(-2);

  const yymmdd = `${YY}${MM}${DD}`;
  return Array.from(yymmdd).map((char) => parseInt(char));
}

export function getHashLen(signatureAlgorithm: string) {
  switch (signatureAlgorithm) {
    case 'sha1WithRSAEncryption':
    case 'ecdsa-with-SHA1':
      return 20;
    case 'sha256WithRSAEncryption':
    case 'rsassaPss':
    case 'ecdsa-with-SHA256':
      return 32;
    case 'sha384WithRSAEncryption':
    case 'ecdsa-with-SHA384':
      return 48;
    case 'sha512WithRSAEncryption':
    case 'ecdsa-with-SHA512':
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

export function generateSMTProof(smt: SMT, leaf: bigint) {
  const {entry, matchingEntry, siblings, root, membership} = smt.createProof(leaf);
  const depth = siblings.length
  
  let closestleaf;
  if (!matchingEntry){ // we got the 0 leaf or membership
    // then check if entry[1] exists
    if(!entry[1]){
      // non membership proof
      closestleaf = BigInt(0); // 0 leaf
    } else {
      closestleaf = BigInt(entry[0]); // leaf itself (memb proof) 
    }
  } else {
    // non membership proof
    closestleaf = BigInt(matchingEntry[0]); // actual closest
  }
  
  // PATH, SIBLINGS manipulation as per binary tree in the circuit 
  siblings.reverse()
  while(siblings.length < 256) siblings.push(BigInt(0)); 

  // ----- Useful for debugging hence leaving as comments -----
  // const binary = entry[0].toString(2)
  // const bits = binary.slice(-depth);
  // let indices = bits.padEnd(256, "0").split("").map(Number)
  // const pathToMatch = num2Bits(256,BigInt(entry[0])) 
  // while(indices.length < 256) indices.push(0);
  // // CALCULATED ROOT FOR TESTING 
  // // closestleaf, depth, siblings, indices, root : needed 
  // let calculatedNode = poseidon3([closestleaf,1,1]);
  // console.log("Initial node while calculating",calculatedNode)
  // console.log(smt.verifyProof(smt.createProof(leaf)))
  // for (let i= 0; i < depth ; i++) {
  //   const childNodes: any = indices[i] ? [siblings[i], calculatedNode] : [calculatedNode, siblings[i]]
  //   console.log(indices[i],childNodes)
  //   calculatedNode = poseidon2(childNodes)
  // }
  // console.log("Actual node", root)
  // console.log("calculated node", calculatedNode)
  // -----------------------------------------------------------

  return {
    root,
    depth,
    closestleaf,
    siblings,   
  };
}

export function generateMerkleProof(imt: LeanIMT, _index: number, maxDepth: number) {
  const { siblings: merkleProofSiblings, index } = imt.generateProof(_index);
  const depthForThisOne = merkleProofSiblings.length;
  // The index must be converted to a list of indices, 1 for each tree level.
  // The circuit tree depth is 20, so the number of siblings must be 20, even if
  // the tree depth is actually 3. The missing siblings can be set to 0, as they
  // won't be used to calculate the root in the circuit.
  const merkleProofIndices: number[] = [];

  for (let i = 0; i < maxDepth; i += 1) {
    merkleProofIndices.push((index >> i) & 1);
    if (merkleProofSiblings[i] === undefined) {
      merkleProofSiblings[i] = BigInt(0);
    }
  }
  return { merkleProofSiblings, merkleProofIndices, depthForThisOne };
}

export function findSubarrayIndex(arr: any[], subarray: any[]): number {
  return arr.findIndex((_, index) => subarray.every((element, i) => element === arr[index + i]));
}

export function extractRSFromSignature(signatureBytes: number[]): { r: string; s: string } {
  const derSignature = Buffer.from(signatureBytes).toString('binary');
  const asn1 = forge.asn1.fromDer(derSignature);
  const signatureAsn1 = asn1.value;

  if (signatureAsn1.length !== 2) {
    throw new Error('Invalid signature format');
  }

  if (!Array.isArray(asn1.value) || asn1.value.length !== 2) {
    throw new Error('Invalid signature format');
  }
  const r = forge.util.createBuffer(asn1.value[0].value as string).toHex();
  const s = forge.util.createBuffer(asn1.value[1].value as string).toHex();

  return { r, s };
}

export function BigintToArray(n: number, k: number, x: bigint) {
  let mod: bigint = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: bigint[] = [];
  var x_temp: bigint = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}

/**
 * Converts a string of maximum 30 characters to a single BigInt.
 * Each byte is represented by three digits in the resulting BigInt.
 * @param str The input string (max 30 characters)
 * @returns A BigInt representing the concatenated byte values
 */
export function stringToNumber(str: string): bigint {
  if (str.length > 30) {
    throw new Error("Input string must not exceed 30 characters");
  }
  return BigInt('1' + Array.from(str)
    .map(char => char.charCodeAt(0).toString().padStart(3, '0'))
    .join(''));
}

/**
* Converts a BigInt (representing concatenated byte values) back to a string.
* @param num The input BigInt
* @returns The reconstructed string
*/
export function numberToString(num: bigint): string {
  const str = num.toString().slice(1); // Remove leading '1'
  const charCodes = str.match(/.{1,3}/g) || [];
  return String.fromCharCode(...charCodes.map(code => parseInt(code, 10)));
}
export function stringToAsciiBigIntArray(str: string): bigint[] {
  let asciiBigIntArray = [];
  for (let i = 0; i < str.length; i++) {
      asciiBigIntArray.push(BigInt(str.charCodeAt(i)));
  }
  return asciiBigIntArray;
}

export function hexToBin(n: string): string {
  let bin = Number(`0x${n[0]}`).toString(2)
  for (let i = 1; i < n.length; i += 1) {
      bin += Number(`0x${n[i]}`).toString(2).padStart(4, "0")
  }
  return bin
}

export function num2Bits(n: number, inValue: bigint): bigint[] {
  const out: bigint[] = new Array(n).fill(BigInt(0));
  let lc1: bigint = BigInt(0);
  let e2: bigint = BigInt(1);

  for (let i = 0; i < n; i++) {
      out[i] = (inValue >> BigInt(i)) & BigInt(1);

      if (out[i] !== BigInt(0) && out[i] !== BigInt(1)) {
          throw new Error("Bit value is not binary.");
      }

      lc1 += out[i] * e2;
      e2 = e2 << BigInt(1);
  }

  if (lc1 !== inValue) {
      throw new Error("Reconstructed value does not match the input.");
  }
  return out;
}