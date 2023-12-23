// import { createCipheriv, createDecipheriv } from 'crypto';
// import { aesCmac } from 'node-aes-cmac';
// import { mac as iso9797Mac, pad, unpad } from '../iso9797.mjs';
// import ab2aba from '../util/ab2aba.mjs';

// const DES_BLOCKSIZE = 8;
// const AES_BLOCKSIZE = 16;
// const MAC_LENGTH = 8;

// const desIv = () => Buffer.alloc(DES_BLOCKSIZE);
// const aesIv = (algorithm) => (kEnc, ssc) => {
//   const cipher = createCipheriv(algorithm, kEnc, Buffer.alloc(AES_BLOCKSIZE));
//   return cipher.update(ssc);
// };
// const desSsc = () => Buffer.alloc(DES_BLOCKSIZE);
// const aesSsc = () => Buffer.alloc(AES_BLOCKSIZE);
// const cmac = (key, data) => aesCmac(key, data, { returnAsBuffer: true });

// class Session {
//   // Doc 9309-11 9.8.6, 9.8.7
//   static algorithms = {
//     'des-ede3-cbc': {
//       blockSize: DES_BLOCKSIZE,
//       iv: desIv,
//       mac: iso9797Mac,
//       ssc: desSsc,
//     },
//     'aes-128-cbc': {
//       blockSize: AES_BLOCKSIZE,
//       iv: aesIv('aes-128-cbc'),
//       mac: cmac,
//       ssc: aesSsc,
//     },
//     'aes-192-cbc': {
//       blockSize: AES_BLOCKSIZE,
//       iv: aesIv('aes-192-cbc'),
//       mac: cmac,
//       ssc: aesSsc,
//     },
//     'aes-256-cbc': {
//       blockSize: AES_BLOCKSIZE,
//       iv: aesIv('aes-256-cbc'),
//       mac: cmac,
//       ssc: aesSsc,
//     },
//   };

//   constructor(algorithm, kEnc, kMac, ssc) {
//     this.algorithm = algorithm;
//     if (algorithm === 'des-ede3-cbc') {
//       this.kEnc = (kEnc.length !== 24) ? ab2aba(kEnc) : kEnc;
//       this.kMac = (kMac.length !== 24) ? ab2aba(kMac) : kMac;
//     } else {
//       this.kEnc = kEnc;
//       this.kMac = kMac;
//     }

//     this.options = this.constructor.algorithms[algorithm];
//     if (!this.options) {
//       throw new Error(`Unknown algorithm ${algorithm}`);
//     }

//     if (ssc) {
//       this.setSSC(ssc);
//     } else {
//       this.resetSSC();
//     }
//   }

//   encrypt(data) {
//     const iv = this.options.iv(this.kEnc, this.ssc);
//     const cipher = createCipheriv(this.algorithm, this.kEnc, iv);
//     cipher.setAutoPadding(false);
//     const update = cipher.update(data);
//     const final = cipher.final();

//     return Buffer.concat([update, final]);
//   }

//   decrypt(data) {
//     const iv = this.options.iv(this.kEnc, this.ssc);
//     const decipher = createDecipheriv(this.algorithm, this.kEnc, iv);
//     decipher.setAutoPadding(false);
//     const update = decipher.update(data);
//     const final = decipher.final();

//     return Buffer.concat([update, final]);
//   }

//   authenticate(data) {
//     const N = Buffer.concat([this.ssc, data]);
//     return this.options.mac(this.kMac, N).slice(0, MAC_LENGTH);
//   }

//   verify(data, mac) {
//     return mac.equals(this.authenticate(data));
//   }

//   setSSC(ssc) {
//     this.ssc = ssc;
//   }

//   resetSSC() {
//     this.ssc = this.options.ssc();
//   }

//   incrementSSC(n = 1n) {
//     // Lower 8 bytes ought to be enough for everyone
//     const offset = this.ssc.length - 8;
//     const tmp = this.ssc.readBigUInt64BE(offset) + n;
//     const ssc = Buffer.alloc(this.ssc.length);
//     ssc.writeBigUInt64BE(tmp, offset);
//     this.ssc = ssc;
//   }

//   decrementSSC(n = 1n) {
//     this.incrementSSC(-n);
//   }

//   addPadding(data) {
//     return pad(this.options.blockSize, data);
//   }

//   removePadding(data) {
//     return unpad(this.options.blockSize, data);
//   }
// }

// export default Session;
