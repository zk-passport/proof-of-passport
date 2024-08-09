import { describe } from 'mocha';
import { assert, expect } from 'chai';
import path from 'path';
const wasm_tester = require('circom_tester').wasm;
import { poseidon1, poseidon6 } from 'poseidon-lite';
import { generateCircuitInputsRegister } from '../../../common/src/utils/generateInputs';
import { mockPassportData_sha256_rsapss_65537 } from '../../../common/src/constants/mockPassportData';

describe('Proof of Passport - Circuits - RSASSAPSS - 2057', function () {
  this.timeout(0);
  let inputs: any;
  let circuit: any;
  let attestation_id: string;
  const n_dsc = 121;
  const k_dsc = 17;

  let passportData = mockPassportData_sha256_rsapss_65537;

  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/tests/rsassapss/rsassapss_2057.circom'),
      {
        include: [
          'node_modules',
          'node_modules/@zk-email/circuits/helpers/sha.circom',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    const secret = BigInt(Math.floor(Math.random() * Math.pow(2, 254))).toString();
    const attestation_name = 'E-PASSPORT';
    attestation_id = poseidon1([BigInt(Buffer.from(attestation_name).readUIntBE(0, 6))]).toString();
    inputs = generateCircuitInputsRegister(secret, secret, attestation_id, passportData, n_dsc, k_dsc);

  });

  it('should compile and load the circuit', async function () {
    expect(circuit).to.not.be.undefined;
  });

  it('should calculate the witness with correct inputs', async function () {
    const w = await circuit.calculateWitness({
      signature: inputs.signature,
      pubkey: inputs.dsc_modulus,
      eContentBytes: inputs.signed_attributes,
    });
    await circuit.checkConstraints(w);
  });

  it('should fail to calculate witness with invalid signature', async function () {
    try {
      const invalidInputs = {
        pubkey: inputs.dsc_modulus,
        eContentBytes: inputs.signed_attributes,
        signature: inputs.signature.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
      };
      await circuit.calculateWitness(invalidInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
    }
  });
});
