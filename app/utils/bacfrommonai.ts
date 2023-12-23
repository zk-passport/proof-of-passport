import {
  createHash,
  randomBytes as _randomBytes,
  createCipheriv,
  createDecipheriv,
} from 'crypto';
import { kdfEnc, kdfMac } from './kdf';
import { transceive } from '../App';
import { promisify } from 'util';
// import { createHash } from "react-native-crypto"
const algorithm = 'des-ede3-cbc';

function xor(a: any, b: any) {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

export function mac(key: Buffer, message: Buffer) {
  const size = message.length / 8;
  let y = Buffer.alloc(8);

  const keya = key.slice(0, 8);
  const keyb = key.slice(8, 16);

  const block = createCipheriv('des-cbc', keya, y);
  for (let i = 0; i < size; i += 1) {
    y = block.update(message.slice(i * 8, i * 8 + 8));
  }

  const desb = createDecipheriv('des-ede3-ecb', Buffer.concat([keyb, keyb, keyb]), null);
  const desa = createCipheriv('des-ede3-ecb', Buffer.concat([keya, keya, keya]), null);

  desb.setAutoPadding(false);
  desa.setAutoPadding(false);

  return desa.update(desb.update(y));
}

export function pad(length: number, buffer: Buffer) {
  const padBlock = Buffer.alloc(length);
  padBlock[0] = 0x80;
  const left = length - (buffer.length % length);
  return Buffer.concat([buffer, padBlock.subarray(0, left)]);
}


export function computeBacKeys(mrzInfo: string): [Buffer, Buffer] {
  const sha1 = createHash('sha1');
  sha1.update(mrzInfo);
  const h = sha1.digest();
  const kSeed = h.subarray(0, 16);

  const kEnc = kdfEnc(algorithm, kSeed);
  const kMac = kdfMac(algorithm, kSeed);

  return [kEnc, kMac];
}

export async function authenticate(bac: {
  keys: [Buffer, Buffer]
  rndIc?: Buffer
}) {
  const { keys, rndIc } = bac;
  const randomBytes = promisify(_randomBytes);
  const rnd = await randomBytes(24);

  const rndIfd = rnd.subarray(0, 8);
  const kIfd = rnd.subarray(8, 24);

  const keysIfd = computeKeysIfd(keys, rndIc as Buffer, rndIfd, kIfd);
  return {
    rndIfd,
    kIfd,
    keysIfd,
  };
}

export function computeKeysIfd(keys: [Buffer, Buffer], rndIc: Buffer, rndIfd: Buffer, kIfd: Buffer) {
  const [kEnc, kMac] = keys;
  const s = Buffer.concat([rndIfd, rndIc, kIfd]);

  const eIfd = computeEifd(kEnc, s);
  const mIfd = mac(kMac, pad(8, eIfd));

  return [eIfd, mIfd];
}

export function computeEifd(kEnc: Buffer, s: Buffer) {
  const iv = Buffer.alloc(8);
  const key = ab2aba(kEnc);

  const cipher = createCipheriv('des-ede3-cbc', key, iv);
  return cipher.update(s);
}


export default function ab2aba(buf: Buffer) {
  return Buffer.concat([buf, buf.slice(0, (buf.length / 2) | 0)]);
}


export function computeSessionKeys(options: any) {
  const { kIfd, keysIc: data } = options;
  const [enc] = options.keys;

  const kEnc = ab2aba(enc);
  const iv = Buffer.alloc(8);
  const decipher = createDecipheriv('des-ede3-cbc', kEnc, iv);

  const res = decipher.update(data);
  const kIc = res.subarray(16, 32);
  const kSeed = xor(kIfd, kIc);

  const ksEnc = kdfEnc(algorithm, kSeed);
  const ksMac = kdfMac(algorithm, kSeed);

  return [ksEnc, ksMac];
}

export function computeSsc(options: any) {
  const { rndIfd, rndIc } = options;
  return Buffer.concat([rndIc.slice(-4), rndIfd.slice(-4)]);
}

export async function performBac(keys: [Buffer, Buffer]) {
  const options: {
    keys: [Buffer, Buffer]
    rndIc?: Buffer
    keysIfd?: any
    keysIc?: Buffer
  } = {
    keys,
  };
  let apdu;
  let res;

  // GET CHALLENGE
  console.log('= Get Challenge');
  const randBytesRes = await transceive([0x00, 0x84, 0x00, 0x00, 0x08]);
  const iccBytes = Buffer.from(randBytesRes.slice(0, randBytesRes.length - 2).map((x: string) => parseInt(x, 16)));
  console.log("iccBytes", iccBytes);

  options.rndIc = iccBytes.slice(0, 8);
  Object.assign(options, await authenticate(options));

  const data = Buffer.concat(options.keysIfd);
  // EXTERNAL(/MUTUAL) AUTHENTICATE
  const keysIcRes = await transceive([0x00, 0x82, 0x00, 0x00, 0x28, ...data]); // bl=42 ??

  options.keysIc = Buffer.from(keysIcRes.map((x: string) => parseInt(x, 16)));

  const [ksEnc, ksMac] = computeSessionKeys(options);
  const ssc = computeSsc(options);
  console.log('ssc', ssc);
  // return new Session('des-ede3-cbc', ksEnc, ksMac, ssc);
}
