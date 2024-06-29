import { poseidon9, poseidon2 } from "poseidon-lite"
import { IMT } from '@zk-kit/imt'
import { stringToAsciiBigIntArray } from "./utils";
import { LeanIMT } from "@zk-kit/lean-imt";

export function buildPassTree(passports :any[]){
    let leaves: bigint[] = []
    let startTime = performance.now();
    for (let i = 0; i < passports.length; i++) {
        const passport = passports[i]

        if (i !== 0) {
          console.log('Processing passport number', i, "out of", passports.length);
        }

        if (passport.Pass_No.length > 9) {
          console.log('passport length is greater than 9:', i, passport)
          continue
        } else if (passport.Pass_No.length < 9){
          while (passport.Pass_No.length != 9) {
            passport.Pass_No += '<'
          }
        }
        
        const leaf = getOfacLeaf(stringToAsciiBigIntArray(passport.Pass_No), i)
        if (!leaf) {
          continue
        }
        leaves.push(leaf)
      } 

    console.log("Total passports paresed are : ", leaves.length," over ",passports.length )

    // What depth is optimal ?
    const tree = new LeanIMT((a, b) => poseidon2([a, b]), leaves);
    console.log('passport tree built in', performance.now() - startTime, 'ms')
    return tree
}

export function getOfacLeaf(passport: any, i?: number): bigint {
  if (passport.length !== 9) {
    console.log('parsed passport length is not 9:', i, passport)
    return
  }
  // change into bigint if not already
  try {
    return poseidon9(passport)
  } catch (err) {
    console.log('err : passport', err, i, passport)
  }
}


