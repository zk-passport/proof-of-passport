export type DataHash = [number, number[]];

export type PassportData = {
  mrz: string;
  signatureAlgorithm: string;
  pubKey: {modulus?: string, exponent?: string, curveName?: string, publicKeyQ?: string};
  dataGroupHashes: DataHash[];
  eContent: number[];
  encryptedDigest: number[];
};
