import { expect } from 'chai';
import path from 'path';
const wasm_tester = require('circom_tester').wasm;
import {
  mockPassportData_sha256_rsa_65537,
  mockPassportData2_sha256_rsa_65537,
} from '../../../common/src/constants/mockPassportData';
import { generateCircuitInputsOfac } from '../../../common/src/utils/generateInputs';
import { getLeaf } from '../../../common/src/utils/pubkeyTree';
import { SMT, ChildNodes } from '@ashpect/smt';
import { poseidon1, poseidon2, poseidon3, poseidon6 } from 'poseidon-lite';
import { LeanIMT } from '@zk-kit/lean-imt';
import { formatMrz, packBytes } from '../../../common/src/utils/utils';
import passportNojson from '../../../common/ofacdata/outputs/passportNoSMT.json';
import nameDobjson from '../../../common/ofacdata/outputs/nameDobSMT.json';
import namejson from '../../../common/ofacdata/outputs/nameSMT.json';
import { PassportData } from '../../../common/src/utils/types';
import exp from 'constants';

let circuit: any;
let passportData = mockPassportData_sha256_rsa_65537; //Mock passport is ADDED in ofac list to test circuits
let passportData2 = mockPassportData2_sha256_rsa_65537; //Mock passport is not added in ofac list to test circuits
let tree: LeanIMT;
const hash = (childNodes: ChildNodes) =>
  childNodes.length === 2 ? poseidon2(childNodes) : poseidon3(childNodes);

// Calculating common validatidy inputs for all 3 ciruits
function getPassportInputs(passportData: PassportData) {
  const secret = BigInt(Math.floor(Math.random() * Math.pow(2, 254))).toString();
  const attestation_name = 'E-PASSPORT';
  const attestation_id = poseidon1([
    BigInt(Buffer.from(attestation_name).readUIntBE(0, 6)),
  ]).toString();

  const majority = '18';
  const user_identifier = '0xE6E4b6a802F2e0aeE5676f6010e0AF5C9CDd0a50';
  const bitmap = Array(90).fill('1');
  const scope = poseidon1([BigInt(Buffer.from('VOTEEEEE').readUIntBE(0, 6))]).toString();

  const pubkey_leaf = getLeaf({
    signatureAlgorithm: passportData.signatureAlgorithm,
    modulus: passportData.pubKey.modulus,
    exponent: passportData.pubKey.exponent,
  }).toString();
  const mrz_bytes = packBytes(formatMrz(passportData.mrz));
  const commitment = poseidon6([
    secret,
    attestation_id,
    pubkey_leaf,
    mrz_bytes[0],
    mrz_bytes[1],
    mrz_bytes[2],
  ]);

  return {
    secret: secret,
    attestation_id: attestation_id,
    passportData: passportData,
    commitment: commitment,
    majority: majority,
    bitmap: bitmap,
    scope: scope,
    user_identifier: user_identifier,
  };
}
const inputs = getPassportInputs(passportData);
const mockInputs = getPassportInputs(passportData2);

tree = new LeanIMT((a, b) => poseidon2([a, b]), []);
tree.insert(BigInt(inputs.commitment));
tree.insert(BigInt(mockInputs.commitment));

// POSSIBLE TESTS (for each of 3 circuits) :
// 0. Cicuits compiles and loads
// 1. Valid proof   : Correct path and corresponding closest leaf AND closest_leaf != pasport_hash ; Valid prove of non-membership
// 2. Invalid proof : Correct path and corresponding closest leaf AND closest_leaf == pasport_hash ; Valid prove of membership ; Hence non-membership proof would fail
// 3. Invalid proof : Correct path but wrong corresponding siblings ; fails due to calculatedRoot != smt_root

// Level 3 : Passport match in OfacList
describe('start testing ofac_passportNo_verifier.circom', function () {
  this.timeout(0);
  let passno_smt = new SMT(hash, true);
  let memSmtInputs: any;
  let nonMemSmtInputs: any;

  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/ofac/ofac_passportNo_verifier.circom'),
      {
        include: [
          'node_modules',
          './node_modules/@zk-kit/binary-merkle-root.circom/src',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    passno_smt.import(passportNojson);
    const proofLevel = 3;
    memSmtInputs = generateCircuitInputsOfac(
      // proof of membership
      inputs.secret,
      inputs.attestation_id,
      inputs.passportData,
      tree,
      inputs.majority,
      inputs.bitmap,
      inputs.scope,
      inputs.user_identifier,
      passno_smt,
      proofLevel
    );

    nonMemSmtInputs = generateCircuitInputsOfac(
      // proof of non-membership
      mockInputs.secret,
      mockInputs.attestation_id,
      mockInputs.passportData,
      tree,
      mockInputs.majority,
      mockInputs.bitmap,
      mockInputs.scope,
      mockInputs.user_identifier,
      passno_smt,
      proofLevel
    );
  });

  // Compile circuit
  it('should compile and load the circuit, level 3', async function () {
    expect(circuit).to.not.be.undefined;
  });

  // Corrct siblings and closest leaf : Everything correct as a proof
  it('should pass without errors , all conditions satisfied', async function () {
    let w = await circuit.calculateWitness(nonMemSmtInputs);
    const proofLevel = await circuit.getOutput(w, ['proofLevel']);
    console.log(proofLevel);
    console.log('Everything correct, Valid proof of non-membership !!');
  });

  // Correct siblings but membership proof : Fail at line 43 assertion
  it('should fail to calculate witness since trying to generate membership proof, level 3', async function () {
    try {
      await circuit.calculateWitness(memSmtInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
      expect(error.message).to.include('line: 43');
      expect(error.message).to.not.include('SMTVerify');
    }
  });

  // Give wrong closest leaf but correct siblings array : Fail of SMT Verification
  it('should fail to calculate witness due to wrong closest_leaf provided, level 3', async function () {
    try {
      let wrongSibInputs = nonMemSmtInputs;
      const randomNumber = Math.floor(Math.random() * Math.pow(2, 254));
      wrongSibInputs.closest_leaf = BigInt(randomNumber).toString();
      await circuit.calculateWitness(wrongSibInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
      expect(error.message).to.include('SMTVerify');
    }
  });
});

// Level 2 : NameDob match in OfacList
describe('start testing ofac_nameDob_verifier.circom', function () {
  this.timeout(0);
  let namedob_smt = new SMT(hash, true);
  let memSmtInputs: any;
  let nonMemSmtInputs: any;

  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/ofac/ofac_nameDob_verifier.circom'),
      {
        include: [
          'node_modules',
          './node_modules/@zk-kit/binary-merkle-root.circom/src',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    namedob_smt.import(nameDobjson);
    const proofLevel = 2;
    memSmtInputs = generateCircuitInputsOfac(
      // proof of membership
      inputs.secret,
      inputs.attestation_id,
      inputs.passportData,
      tree,
      inputs.majority,
      inputs.bitmap,
      inputs.scope,
      inputs.user_identifier,
      namedob_smt,
      proofLevel
    );

    nonMemSmtInputs = generateCircuitInputsOfac(
      // proof of non-membership
      mockInputs.secret,
      mockInputs.attestation_id,
      mockInputs.passportData,
      tree,
      mockInputs.majority,
      mockInputs.bitmap,
      mockInputs.scope,
      mockInputs.user_identifier,
      namedob_smt,
      proofLevel
    );
  });

  // Compile circuit
  it('should compile and load the circuit, level 2', async function () {
    expect(circuit).to.not.be.undefined;
  });

  // Corrct siblings and closest leaf : Everything correct as a proof
  it('should pass without errors , all conditions satisfied', async function () {
    let w = await circuit.calculateWitness(nonMemSmtInputs);
    const proofLevel = await circuit.getOutput(w, ['proofLevel']);
    console.log(proofLevel);
    console.log('Everything correct, Valid proof of non-membership !!');
  });

  // Correct siblings but membership proof : Fail at line 54 assertion
  it('should fail to calculate witness since trying to generate membership proof, level 2', async function () {
    try {
      await circuit.calculateWitness(memSmtInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
      expect(error.message).to.include('line: 54');
      expect(error.message).to.not.include('SMTVerify');
    }
  });

  // Give wrong closest leaf but correct siblings array
  it('should fail to calculate witness due to wrong closest_leaf provided, level 2', async function () {
    try {
      let wrongSibInputs = nonMemSmtInputs;
      const randomNumber = Math.floor(Math.random() * Math.pow(2, 254));
      wrongSibInputs.closest_leaf = BigInt(randomNumber).toString();
      await circuit.calculateWitness(wrongSibInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
      expect(error.message).to.include('SMTVerify');
    }
  });
});

// Level 1 : Name match in OfacList
describe('start testing ofac_name_verifier.circom', function () {
  this.timeout(0);
  let name_smt = new SMT(hash, true);
  let memSmtInputs: any;
  let nonMemSmtInputs: any;

  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/ofac/ofac_name_verifier.circom'),
      {
        include: [
          'node_modules',
          './node_modules/@zk-kit/binary-merkle-root.circom/src',
          './node_modules/circomlib/circuits',
        ],
      }
    );

    name_smt.import(namejson);
    const proofLevel = 1;
    memSmtInputs = generateCircuitInputsOfac(
      // proof of membership
      inputs.secret,
      inputs.attestation_id,
      inputs.passportData,
      tree,
      inputs.majority,
      inputs.bitmap,
      inputs.scope,
      inputs.user_identifier,
      name_smt,
      proofLevel
    );

    nonMemSmtInputs = generateCircuitInputsOfac(
      // proof of non-membership
      mockInputs.secret,
      mockInputs.attestation_id,
      mockInputs.passportData,
      tree,
      mockInputs.majority,
      mockInputs.bitmap,
      mockInputs.scope,
      mockInputs.user_identifier,
      name_smt,
      proofLevel
    );
  });

  // Compile circuit
  it('should compile and load the circuit, level 1', async function () {
    expect(circuit).to.not.be.undefined;
  });

  // Corrct siblings and closest leaf : Everything correct as a proof
  it('should pass without errors , all conditions satisfied', async function () {
    let w = await circuit.calculateWitness(nonMemSmtInputs);
    const proofLevel = await circuit.getOutput(w, ['proofLevel']);
    console.log(proofLevel);
    console.log('Everything correct, Valid proof of non-membership !!');
  });

  // Correct siblings but membership proof : Fail at line 46 assertion
  it('should fail to calculate witness since trying to generate membership proof, level 1', async function () {
    try {
      await circuit.calculateWitness(memSmtInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
      expect(error.message).to.include('line: 46');
      expect(error.message).to.not.include('SMTVerify');
    }
  });

  // Give wrong closest leaf but correct siblings array
  it('should fail to calculate witness due to wrong closest_leaf provided, level 1', async function () {
    try {
      let wrongSibInputs = nonMemSmtInputs;
      const randomNumber = Math.floor(Math.random() * Math.pow(2, 254));
      wrongSibInputs.closest_leaf = BigInt(randomNumber).toString();
      await circuit.calculateWitness(wrongSibInputs);
      expect.fail('Expected an error but none was thrown.');
    } catch (error) {
      expect(error.message).to.include('Assert Failed');
      expect(error.message).to.include('SMTVerify');
    }
  });
});
