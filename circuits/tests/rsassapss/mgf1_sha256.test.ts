import path from 'path';
import { createHash, randomBytes } from 'node:crypto';
const wasm_tester = require('circom_tester').wasm;

describe('Mgf1_sha256 Circuit Test', function () {
  this.timeout(0); // Disable timeout
  const hashLen = 32; // SHA256 length

  const compileCircuit = async (circuitPath: string) => {
    return await wasm_tester(path.join(circuitPath), {
      include: ['node_modules'],
    });
  };

  function buffer2bitArray(b) {
    const res = [];
    for (let i = 0; i < b.length; i++) {
      for (let j = 0; j < 8; j++) {
        res.push((b[i] >> (7 - j)) & 1);
      }
    }
    return res;
  }

  function num2Bits(n, input) {
    let out = [];
    for (let i = 0; i < n; i++) {
      out[i] = (input >> i) & 1;
    }
    return out;
  }

  const bitArray2buffer = (a) => {
    const len = Math.floor((a.length - 1) / 8) + 1;
    const b = Buffer.alloc(len);

    for (let i = 0; i < a.length; i++) {
      const p = Math.floor(i / 8);
      b[p] = b[p] | (Number(a[i]) << (7 - (i % 8)));
    }
    return b;
  };

  const MGF1 = (mgfSeed: Buffer, maskLen: number) => {
    const hLen = hashLen;
    if (maskLen > 0xffffffff * hLen) {
      throw new Error('mask too long');
    }

    var T = [];
    for (var i = 0; i <= Math.ceil(maskLen / hLen) - 1; i++) {
      var C = Buffer.alloc(4);
      C.writeUInt32BE(i);
      const hash3 = createHash('sha256');
      hash3.update(Buffer.concat([mgfSeed, C]));
      T.push(hash3.digest());
    }
    return Buffer.concat(T).slice(0, maskLen);
  };

  it('Should compile', async function () {
    await compileCircuit('circuits/tests/mgf1Sha256/Mgf1Sha256_tester.circom');
  });

  it('Should generate correct MGF1 output - 4 Byte Seed', async function () {
    const seed = 12345678;
    const maskLen = 32;
    const seedLen = 4; // 4 bytes - set in the circuit

    const bitArray = num2Bits(seedLen * 8, seed);
    const mgfSeed = bitArray2buffer(bitArray);

    const expected = MGF1(mgfSeed, maskLen);

    const circuit = await compileCircuit('circuits/tests/mgf1Sha256/Mgf1Sha256_tester.circom');
    const expected_mask_output = buffer2bitArray(expected);
    const inputs = {
      seed: seed,
      expected_mask_output,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(witness);
  });

  it('Should generate correct MGF1 output - 32 Byte Seed', async function () {
    const randBytes = randomBytes(32);

    const maskLen = 32;
    const seedLen = 32; // set in circuit
    const expected = MGF1(randBytes, maskLen);

    const circuit = await compileCircuit(
      'circuits/tests/mgf1Sha256/Mgf1Sha256_32Bytes_tester.circom'
    );
    const expected_mask_output = buffer2bitArray(expected);
    const inputs = {
      seed: buffer2bitArray(randBytes),
      expected_mask_output,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(witness);
  });

  it('Should generate correct MGF1 output - seedLen value > than actual seed length', async function () {
    const seed = 1234;
    const maskLen = 32;
    const seedLen = 4; //set in circuit

    const bitArray = num2Bits(seedLen * 8, seed);
    const mgfSeed = bitArray2buffer(bitArray);

    const expected = MGF1(mgfSeed, maskLen);

    const circuit = await compileCircuit('circuits/tests/mgf1Sha256/Mgf1Sha256_tester.circom');
    const expected_mask_output = buffer2bitArray(expected);
    const inputs = {
      seed: seed,
      expected_mask_output,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(witness);
  });

  it('Should generate correct MGF1 output - maskLen == 1', async function () {
    const seed = 12345678;
    const maskLen = 1;
    const seedLen = 4;

    const bitArray = num2Bits(seedLen * 8, seed);
    const mgfSeed = bitArray2buffer(bitArray);

    const expected = MGF1(mgfSeed, maskLen);

    const circuit = await compileCircuit(
      'circuits/tests/mgf1Sha256/Mgf1Sha256_1ByteMask_tester.circom'
    );
    const expected_mask_output = buffer2bitArray(expected);
    const inputs = {
      seed: seed,
      expected_mask_output,
    };

    const witness = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(witness);
  });
});
