import cryptoES from "crypto-es";
import CryptoJS from 'crypto-js';
import { transceive } from "../App";

function keyDerivation(key: string, constant: Uint8Array) {
  if (constant[3] !== 0 && constant[3] !== 1) {
    throw new Error("Bad parameter (c=0 or c=1)");
  }
  const keyBytes = CryptoJS.enc.Hex.parse(key);
  const constantBytes = CryptoJS.enc.Hex.parse(constant.toString());
  const concat = CryptoJS.lib.WordArray.create().concat(keyBytes).concat(constantBytes);
  console.log("\tConcatenate Kseed and c");
  console.log("\t\tD: " + concat.toString(CryptoJS.enc.Hex));
  const hash = CryptoJS.SHA1(concat);
  console.log("\tCalculate the SHA-1 hash of D");
  console.log("\t\tHsha1(D): " + hash.toString(CryptoJS.enc.Hex));
  const Ka = hash.toString(CryptoJS.enc.Hex).slice(0, 8);
  const Kb = hash.toString(CryptoJS.enc.Hex).slice(8, 16);
  console.log("\tForm keys Ka and Kb");
  console.log("\t\tKa: " + Ka);
  console.log("\t\tKb: " + Kb);
  const KaParity = adjustParityBits(Ka);
  const KbParity = adjustParityBits(Kb);
  console.log("\tAdjust parity bits");
  console.log("\t\tKa: " + KaParity);
  console.log("\t\tKb: " + KbParity);
  return KaParity + KbParity;
}

function adjustParityBits(key: string) {
  let keyBin = parseInt(key, 16).toString(2);
  keyBin = keyBin.length % 8 ? '0'.repeat(8 - keyBin.length % 8) + keyBin : keyBin;
  let keyBinParity = '';
  for (let i = 0; i < keyBin.length; i += 7) {
    const byte = keyBin.slice(i, i + 7);
    keyBinParity += byte + (byte.split('1').length % 2 ? '0' : '1');
  }
  return parseInt(keyBinParity, 2).toString(16).toUpperCase();
}

function pad(toPad: string) {
    const size = 8;
    const padBlock = '\x80' +  '\x00'.repeat(7);
    const left = size - (toPad.length % size);
    return (toPad + padBlock.slice(0, left));
}

function mac(key: string, msg: string) {
  const size = Math.floor(msg.length / 8);
  let y = cryptoES.enc.Hex.parse('0000000000000000'); // Equivalent to '\0'.repeat(8)
  let keyPart1 = cryptoES.enc.Utf8.parse(key.slice(0, 8));
  let keyPart2 = cryptoES.enc.Utf8.parse(key.slice(8, 16));
  
  for (let i = 0; i < size; i++) {
      let block = cryptoES.enc.Utf8.parse(msg.slice(i * 8, i * 8 + 8));
      let encrypted = cryptoES.TripleDES.encrypt(block, keyPart1, { iv: y, mode: cryptoES.mode.CBC, padding: cryptoES.pad.NoPadding });
      y = encrypted.ciphertext as cryptoES.lib.WordArray;
  }

  let decrypted = cryptoES.TripleDES.decrypt({ ciphertext: y }, keyPart2, { mode: cryptoES.mode.ECB, padding: cryptoES.pad.NoPadding });
  let finalEncrypted = cryptoES.TripleDES.encrypt(decrypted, keyPart1, { mode: cryptoES.mode.ECB, padding: cryptoES.pad.NoPadding });

  return finalEncrypted.toString();
}

const BAC = {
  KENC: new Uint8Array([0, 0, 0, 1]),
  KMAC: new Uint8Array([0, 0, 0, 2]),
};

export async function doBAC(kmrz: string) {
  const randBytesRes = await transceive([0x00, 0x84, 0x00, 0x00, 0x08]);
  if (randBytesRes[randBytesRes.length - 2] === "90" && randBytesRes[randBytesRes.length - 1] === "0") {
    console.log('bytes requested successfully:');
  }
  const iccBytes = randBytesRes.slice(0, randBytesRes.length - 2);
  console.log("iccBytes", iccBytes);

  const ifdRand = ["18", "51", "C0", "7E", "F6", "FC", "BE", "FD"]
  const kifdRand = ["50", "A8", "CB", "20", "A5", "F1", "5C", "BF", "7A", "5A", "FD", "B6", "5E", "91", "87", "02"]
  const concat = ifdRand.concat(iccBytes, kifdRand);
  
  const kseed = CryptoJS.SHA1(kmrz).toString();
  console.log('kseed', kseed);
  const kseedFirst16 = kseed.slice(0, 16);
  const kenc = keyDerivation(kseedFirst16, BAC.KENC)
  const kmac = keyDerivation(kseedFirst16, BAC.KMAC)

  const eifd = cryptoES.TripleDES.encrypt(
    concat.join(''),
    kenc,
    { mode: cryptoES.mode.CBC, padding: cryptoES.pad.NoPadding } // iv = "0000000000000000" ?
  ).toString();
  
  const mifd = mac(kmac, pad(eifd));
  const cmd_data = eifd + mifd;

  console.log('cmd_data', cmd_data);
  const bacKey = cmd_data
  const bacKeyLength = bacKey.length / 2;
  const bacKeyArray = (bacKey.match(/.{1,2}/g) as string[]).map(Number);
  const mutualAuthResponse = await transceive([0x00, 0x82, 0x00, 0x00, 0x02, bacKeyLength, ...bacKeyArray, 0x28])
  console.log("mutual auth response", mutualAuthResponse);
  const data = mutualAuthResponse.slice(0, mutualAuthResponse.length - 2).join('');
  const { KSenc, KSmac, ssc } = sessionKeys(data, kenc, kifdRand.join(''), iccBytes.join(''), ifdRand.join(''));
  console.log("KSenc", KSenc);
  console.log("KSmac", KSmac);
  console.log("scc", ssc);

}

export function sessionKeys(data: string, ksenc: string, kifd: string, rnd_icc: string, rnd_ifd: string) {
  const decrypted = cryptoES.TripleDES.decrypt({ ciphertext: cryptoES.enc.Hex.parse(data.slice(0, 32)) }, ksenc, { mode: cryptoES.mode.CBC, padding: cryptoES.pad.NoPadding });
  const response = decrypted.toString(cryptoES.enc.Hex);
  const response_kicc = response.slice(16, 32);
  const Kseed = xor(kifd, response_kicc);

  const KSenc = keyDerivation(Kseed, BAC.KENC);
  const KSmac = keyDerivation(Kseed, BAC.KMAC);

  const ssc = rnd_icc.slice(-4) + rnd_ifd.slice(-4);
  return {KSenc, KSmac, ssc};
};

function xor(kifd: string, response_kicc: string) {
  let kseed = "";
  for (let i = 0; i < kifd.length; i++) {
    kseed += String.fromCharCode(kifd.charCodeAt(i) ^ response_kicc.charCodeAt(i));
    //kseed += ((parseInt(kifd[i], 16) ^ parseInt(response_kicc[i], 16)).toString(16)).slice(-2);
  }
  //return hexRepToBin(kseed);
  return kseed;
}
