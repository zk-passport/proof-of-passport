import { poseidon12, poseidon2, poseidon8 } from "poseidon-lite"
import { SignatureAlgorithm, TREE_DEPTH } from "../constants/constants";
import { IMT } from '@zk-kit/imt'
import { bigIntToChunkedBytes, formatSigAlg } from "./utils";

export function buildPubkeyTree(pubkeys: any[]) {
  const tree = new IMT(poseidon2, TREE_DEPTH, 0) // 0 as zerovalue

  for(let i = 0; i < pubkeys.length; i++) {
    const pubkey = pubkeys[i]
    const sigAlgFormatted = formatSigAlg(pubkey.signatureAlgorithm, pubkey.exponent)

    let leaf: bigint | undefined;

    if (i % 3000 === 0 && i !== 0) {
      console.log('Processing pubkey number', i, "over", pubkeys.length);
    }

    if (
      sigAlgFormatted === "sha256WithRSAEncryption_65537"
      || sigAlgFormatted === "sha256WithRSAEncryption_3"
      || sigAlgFormatted === "sha1WithRSAEncryption_65537"
      || sigAlgFormatted === "rsassaPss_65537"
      || sigAlgFormatted === "rsassaPss_3"
      || sigAlgFormatted === "sha512WithRSAEncryption_65537"
    ) {
      // Converting pubkey.modulus into 11 chunks of 192 bits, assuming it is originally 2048 bits.
      // This is because Poseidon circuit only supports an array of 16 elements, and field size is 254.
      const pubkeyChunked = bigIntToChunkedBytes(BigInt(pubkey.modulus), 192, 11);
      // console.log('pubkeyChunked', pubkeyChunked.length, pubkeyChunked)
      try {
        // leaf is poseidon(signatureAlgorithm, ...pubkey)
        leaf = poseidon12([SignatureAlgorithm[sigAlgFormatted], ...pubkeyChunked])
      } catch(err) {
        console.log('err', err, i, sigAlgFormatted, pubkey)
      }
    } else if (
      sigAlgFormatted === "ecdsa_with_SHA1"
      || sigAlgFormatted === "ecdsa_with_SHA384"
      || sigAlgFormatted === "ecdsa_with_SHA256"
      || sigAlgFormatted === "ecdsa_with_SHA512"
    ) {
      try {
        leaf = poseidon8([SignatureAlgorithm[sigAlgFormatted], pubkey.pub, pubkey.prime, pubkey.a, pubkey.b, pubkey.generator, pubkey.order, pubkey.cofactor])
      } catch(err) {
        console.log('err', err, i, sigAlgFormatted, pubkey)
      }

    } else {
      console.log('no leaf for this weird signature:', i, sigAlgFormatted)
      continue
    }

    tree.insert(leaf)
  }
  return tree
}