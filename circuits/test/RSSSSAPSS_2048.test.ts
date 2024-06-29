import { describe } from 'mocha'
import { assert, expect } from 'chai'
import path from "path";
const wasm_tester = require("circom_tester").wasm;
import { poseidon1, poseidon6 } from "poseidon-lite";
import { generateCircuitInputsRegister } from '../../common/src/utils/generateInputs';
import { assembleEContent, formatAndConcatenateDataHashes, formatMrz, hash, packBytes } from '../../common/src/utils/utils';
import { PassportData } from '../../common/src/utils/types';
import * as forge from 'node-forge';
import crypto from 'crypto';


describe("Proof of Passport - Circuits - RSASSAPSS - 2048", function () {
    this.timeout(0);
    let inputs: any;
    let circuit: any;
    let attestation_id: string;

    const sampleMRZ = "P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02"
    const sampleDataHashes = [
        [
            2,
            [-66, 82, -76, -21, -34, 33, 79, 50, -104, -120, -114, 35, 116, -32, 6, -14, -100, -115, -128, -8, 10, 61, 98, 86, -8, 45, -49, -46, 90, -24, -81, 38]
        ],
        [
            3,
            [0, -62, 104, 108, -19, -10, 97, -26, 116, -58, 69, 110, 26, 87, 17, 89, 110, -57, 108, -6, 36, 21, 39, 87, 110, 102, -6, -43, -82, -125, -85, -82]
        ],
        [
            11,
            [-120, -101, 87, -112, 111, 15, -104, 127, 85, 25, -102, 81, 20, 58, 51, 75, -63, 116, -22, 0, 60, 30, 29, 30, -73, -115, 72, -9, -1, -53, 100, 124]
        ],
        [
            12,
            [41, -22, 106, 78, 31, 11, 114, -119, -19, 17, 92, 71, -122, 47, 62, 78, -67, -23, -55, -42, 53, 4, 47, -67, -55, -123, 6, 121, 34, -125, 64, -114]
        ],
        [
            13,
            [91, -34, -46, -63, 62, -34, 104, 82, 36, 41, -118, -3, 70, 15, -108, -48, -100, 45, 105, -85, -15, -61, -71, 43, -39, -94, -110, -55, -34, 89, -18, 38]
        ],
        [
            14,
            [76, 123, -40, 13, 51, -29, 72, -11, 59, -63, -18, -90, 103, 49, 23, -92, -85, -68, -62, -59, -100, -69, -7, 28, -58, 95, 69, 15, -74, 56, 54, 38]
        ]
    ] as [number, number[]][]
    const signatureAlgorithm = 'sha256WithRSASSAPSS'
    const hashLen = 32

    function genMockPassportData_sha256WithRSASSAPSS_65537(): PassportData {
        const keypair = forge.pki.rsa.generateKeyPair(2048);
        const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

        const publicKey = keypair.publicKey;
        const modulus = publicKey.n.toString(10);
        const exponent = publicKey.e.toString(10);
        const salt = Buffer.from('dee959c7e06411361420ff80185ed57f3e6776afdee959c7e064113614201420', 'hex');

        const mrzHash = hash(signatureAlgorithm, formatMrz(sampleMRZ));
        const concatenatedDataHashes = formatAndConcatenateDataHashes(
            [[1, mrzHash], ...sampleDataHashes],
            hashLen,
            30
        );

        const eContent = assembleEContent(hash(signatureAlgorithm, concatenatedDataHashes));

        const my_message = Buffer.from(eContent);
        const hash_algorithm = 'sha256';

        const private_key = {
            key: privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: salt.length,
        };

        const signature = crypto.sign(hash_algorithm, my_message, private_key);
        const signatureArray = Array.from(signature, byte => byte < 128 ? byte : byte - 256);

        return {
            mrz: sampleMRZ,
            signatureAlgorithm: signatureAlgorithm,
            pubKey: {
                modulus: modulus,
                exponent: exponent,
            },
            dataGroupHashes: concatenatedDataHashes,
            eContent: eContent,
            encryptedDigest: signatureArray,
            photoBase64: "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABjElEQVR42mL8//8/AyUYiBQYmIw3..."
        }
    }

    let passportData = genMockPassportData_sha256WithRSASSAPSS_65537();


    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits/tests/RSASSAPSS/rsassapss_2048.circom"),
            {
                include: [
                    "node_modules",
                    "node_modules/@zk-email/circuits/helpers/sha.circom",
                    // "./node_modules/@zk-kit/binary-merkle-root.circom/src",
                    "./node_modules/circomlib/circuits"
                ]
            },
        );

        const secret = BigInt(Math.floor(Math.random() * Math.pow(2, 254))).toString();
        console.log("secret", secret);

        const attestation_name = "E-PASSPORT";
        attestation_id = poseidon1([
            BigInt(Buffer.from(attestation_name).readUIntBE(0, 6))
        ]).toString();

        inputs = generateCircuitInputsRegister(
            secret,
            attestation_id,
            passportData,
            [passportData],
        );
    });

    it("should compile and load the circuit", async function () {
        expect(circuit).to.not.be.undefined;
    });

    it("should calculate the witness with correct inputs", async function () {
        const w = await circuit.calculateWitness({
            signature: inputs.signature,
            pubkey: inputs.pubkey,
            eContentBytes: inputs.signed_attributes,
        });
        await circuit.checkConstraints(w);
    });

    it("should fail to calculate witness with invalid signature", async function () {
        try {
            const invalidInputs = {
                pubkey: inputs.pubkey,
                eContentBytes: inputs.signed_attributes,
                signature: inputs.signature.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
            }
            await circuit.calculateWitness(invalidInputs);
            expect.fail("Expected an error but none was thrown.");
        } catch (error) {
            expect(error.message).to.include("Assert Failed");
        }
    });

});