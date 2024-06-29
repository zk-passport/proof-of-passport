import { assert, expect } from 'chai'
import path from "path";
const wasm_tester = require("circom_tester").wasm;
import { mockPassportData_sha256WithRSAEncryption_65537 } from '../../common/src/utils/mockPassportData';
import { formatMrz } from '../../common/src/utils/utils';
import { poseidon2 } from "poseidon-lite";
import { LeanIMT } from "@zk-kit/lean-imt";
import serializedTree from "../../common/ofacdata/passport_tree.json"
import { getOfacLeaf } from '../../common/src/utils/passportTree';
import { generateCircuitInputsDiscloseOfac } from '../../common/src/utils/generateInputs';
import { stringToAsciiBigIntArray } from "../../common/src/utils/utils";

describe("start testing disclose.circom", function () {
    this.timeout(0);
    let inputs: any;
    let circuit: any;
    let w: any;
    let passportData = mockPassportData_sha256WithRSAEncryption_65537;
    let tree: any;

    before(async () => {
        circuit = await wasm_tester(path.join(__dirname, "../circuits/disclose_ofac.circom"),
            {
                include: [
                    "node_modules",
                    "./node_modules/@zk-kit/binary-merkle-root.circom/src",
                    "./node_modules/circomlib/circuits"
                ]
            },
        );

        tree = new LeanIMT<any>((a, b) => poseidon2([a, b]), []);
        let deepcopy = JSON.parse(JSON.stringify(serializedTree));
        tree.import(deepcopy); // copying from json after writing changes leaf to type strings
        const leaves = tree.leaves 
        // console.log(typeof(leaves[0]))
        // console.log(typeof(tree.root))
            
        inputs = generateCircuitInputsDiscloseOfac(
            passportData,
            tree,
        );
    });

    it("should compile and load the circuit", async function () {
        expect(circuit).to.not.be.undefined;
    });

    it("should give a bool if passport exists in ofac list", async function () {
        w = await circuit.calculateWitness(inputs);
        const isEqual = (await circuit.getOutput(w, ["out"]));
        console.log("Bool Value", isEqual)
    });
});