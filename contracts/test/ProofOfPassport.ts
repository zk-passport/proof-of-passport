import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect, assert } from "chai";
import { ethers } from "hardhat";
import { DataHash } from "../../common/src/utils/types";
import { genSampleData } from "../../common/src/utils/passportData";
import { buildPubkeyTree } from "../../common/src/utils/pubkeyTree";
import { attributeToPosition, SignatureAlgorithm } from "../../common/src/constants/constants";
import { formatMrz, splitToWords, formatAndConcatenateDataHashes, toUnsignedByte, hash, bytesToBigDecimal, formatSigAlg, bigIntToChunkedBytes, formatRoot } from "../../common/src/utils/utils";
import { groth16 } from 'snarkjs'
import { countryCodes } from "../../common/src/constants/constants";
import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { poseidon12 } from "poseidon-lite"

import axios from 'axios';
import { DataHexString } from "ethers/lib.commonjs/utils/data";
const fs = require('fs');


describe("Proof of Passport", function () {
  this.timeout(0);

  let passportData, pubkeys, proof, tree, inputs, publicSignals, revealChars, root: DataHexString, callData: any;

  before(async function generateProof() {
    pubkeys = JSON.parse(fs.readFileSync("../common/pubkeys/publicKeysParsed.json") as unknown as string)
    passportData = genSampleData();

    // for testing purposes
    pubkeys = pubkeys.slice(0, 100);
    pubkeys.push({
      signatureAlgorithm: passportData.signatureAlgorithm,
      issuer: 'C = TS, O = Government of Syldavia, OU = Ministry of tests, CN = CSCA-TEST',
      modulus: passportData.pubKey.modulus,
      exponent: passportData.pubKey.exponent
    })
    
    tree = buildPubkeyTree(pubkeys);
    
    const formattedMrz = formatMrz(passportData.mrz);
    const mrzHash = hash(formatMrz(passportData.mrz));
    const concatenatedDataHashes = formatAndConcatenateDataHashes(
      mrzHash,
      passportData.dataGroupHashes as DataHash[],
    );

    const attributeToReveal = {
      issuing_state: true,
      name: true,
      passport_number: true,
      nationality: true,
      date_of_birth: true,
      gender: true,
      expiry_date: true,
    }

    const bitmap = Array(88).fill('1');

    const sigAlgFormatted = formatSigAlg(passportData.signatureAlgorithm, passportData.pubKey.exponent)
    const pubkeyChunked = bigIntToChunkedBytes(BigInt(passportData.pubKey.modulus as string), 192, 11);
    const leaf = poseidon12([SignatureAlgorithm[sigAlgFormatted as keyof typeof SignatureAlgorithm], ...pubkeyChunked])

    const index = tree.indexOf(leaf)
    const mkProof = tree.createProof(index)
    root = tree.root

    Object.entries(attributeToReveal).forEach(([attribute, reveal]) => {
      if (reveal) {
        const [start, end] = attributeToPosition[attribute as keyof typeof attributeToPosition];
        bitmap.fill('1', start, end + 1);
      }
    });

    inputs = {
      mrz: formattedMrz.map(byte => String(byte)),
      reveal_bitmap: bitmap.map(byte => String(byte)),
      dataHashes: concatenatedDataHashes.map(toUnsignedByte).map(byte => String(byte)),
      eContentBytes: passportData.eContent.map(toUnsignedByte).map(byte => String(byte)),
      pubkey: splitToWords(
        BigInt(passportData.pubKey.modulus as string),
        BigInt(64),
        BigInt(32)
      ),
      signature: splitToWords(
        BigInt(bytesToBigDecimal(passportData.encryptedDigest)),
        BigInt(64),
        BigInt(32)
      ),
      signatureAlgorithm: SignatureAlgorithm[sigAlgFormatted as keyof typeof SignatureAlgorithm],
      pathIndices: mkProof.pathIndices,
      siblings: mkProof.siblings.flat(),
      root: root,
      address: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", // hardhat account 1
    }

    console.log('generating proof...');
    ({ proof, publicSignals } = await groth16.fullProve(
      inputs,
      "../circuits/build/proof_of_passport_js/proof_of_passport.wasm",
      "../circuits/build/proof_of_passport_final.zkey"
    ))

    console.log('proof done');

    revealChars = publicSignals.slice(0, 88).map((byte: string) => String.fromCharCode(parseInt(byte, 10))).join('');

    const vKey = JSON.parse(fs.readFileSync("../circuits/build/proof_of_passport_vkey.json"));
    const verified = await groth16.verify(
      vKey,
      publicSignals,
      proof
    )

    assert(verified == true, 'Should verify')

    const cd = await groth16.exportSolidityCallData(proof, publicSignals);
    callData = JSON.parse(`[${cd}]`);
    console.log('callData', callData);
  });

  describe("Proof of Passport SBT", function () {
    async function deployHardhatFixture() {
      const [owner, otherAccount, thirdAccount] = await ethers.getSigners();

      const Verifier = await ethers.getContractFactory("Groth16Verifier");
      const verifier = await Verifier.deploy();
      await verifier.waitForDeployment();
    
      console.log(`Verifier deployed to ${verifier.target}`);

      const Formatter = await ethers.getContractFactory("Formatter");
      const formatter = await Formatter.deploy();
      await formatter.waitForDeployment();
      await formatter.addCountryCodes(Object.entries(countryCodes));

      console.log(`Formatter deployed to ${formatter.target}`);

      const Registry = await ethers.getContractFactory("Registry");
      const registry = await Registry.deploy(formatRoot(root));
      await registry.waitForDeployment();

      console.log(`Registry deployed to ${registry.target}`);

      const ProofOfPassport = await ethers.getContractFactory("ProofOfPassport");
      const proofOfPassport = await ProofOfPassport.deploy(verifier.target, formatter.target, registry.target);
      await proofOfPassport.waitForDeployment();
    
      console.log(`ProofOfPassport NFT deployed to ${proofOfPassport.target}`);

      return {verifier, proofOfPassport, formatter, owner, otherAccount, thirdAccount}
    }

    it("Verifier verifies a correct proof", async () => {
      const { verifier } = await loadFixture(deployHardhatFixture);

      expect(
        await verifier.verifyProof(callData[0], callData[1], callData[2], callData[3])
      ).to.be.true;
    });

    it("Should allow SBT minting", async function () {
      const { proofOfPassport, otherAccount, thirdAccount } = await loadFixture(
        deployHardhatFixture
      );

      await proofOfPassport
        .connect(thirdAccount) // fine that it's not the same account as address is taken from the proof
        .mint(...callData);

      expect(await proofOfPassport.balanceOf(otherAccount.address)).to.equal(1);
    });

    it("Shouldn't allow minting with an invalid proof", async function () {
      const { proofOfPassport, otherAccount } = await loadFixture(
        deployHardhatFixture
      );

      const badCallData = JSON.parse(JSON.stringify(callData));

      badCallData[0][1] = "0x1cdbaf59a0439d55f19162ee0be5a501f5b55c669a6e1f8d27b75d95ff31ff7b";

      expect(
        proofOfPassport
          .connect(otherAccount)
          .mint(...badCallData as any)
      ).to.be.revertedWith("Invalid proof");
    });

    it("Should have a correct tokenURI a user to mint a SBT", async function () {
      const { proofOfPassport, otherAccount } = await loadFixture(
        deployHardhatFixture
      );

      console.log('callData', callData)

      const tx = await proofOfPassport
        .connect(otherAccount)
        .mint(...callData);

      await tx.wait();

      const tokenURI = await proofOfPassport.tokenURI(0);

      console.log('tokenURI', tokenURI);

      const decodedTokenURI = Buffer.from(tokenURI.split(',')[1], 'base64').toString();
      let parsedTokenURI;

      try {
        parsedTokenURI = JSON.parse(decodedTokenURI);
      } catch (e) {
        assert(false, 'TokenURI is not a valid JSON');
      }
      console.log('parsedTokenURI', parsedTokenURI);
    });

    it("Should convert ISO dates to unix timestamps correctly", async function () {
      const { formatter } = await loadFixture(
        deployHardhatFixture
      );

      const unix_timestamp = await formatter.dateToUnixTimestamp("230512") // 2023 05 12
      console.log('unix_timestamp', unix_timestamp.toString());

      var date = new Date(Number(unix_timestamp) * 1000);
      console.log("date:", date.toUTCString());

      expect(date.getUTCFullYear()).to.equal(2023);
      expect(date.getUTCMonth()).to.equal(4);
      expect(date.getUTCDate()).to.equal(12);
    })

    it("Should support expiry", async function () {
      const { proofOfPassport, otherAccount } = await loadFixture(
        deployHardhatFixture
      );

      const tx = await proofOfPassport
      .connect(otherAccount)
      .mint(...callData);

      await tx.wait();

      const tokenURI = await proofOfPassport.tokenURI(0);
      const decodedTokenURI = Buffer.from(tokenURI.split(',')[1], 'base64').toString();
      const parsedTokenURI = JSON.parse(decodedTokenURI);

      const expired = parsedTokenURI.attributes.find((attribute: any) => attribute.trait_type === 'Expired');
      expect(expired.value).to.equal('No');

      await time.increaseTo(2240161656); // 2040

      const tokenURIAfter = await proofOfPassport.tokenURI(0);
      const decodedTokenURIAfter = Buffer.from(tokenURIAfter.split(',')[1], 'base64').toString();
      const parsedTokenURIAfter = JSON.parse(decodedTokenURIAfter);

      const expiredAfter = parsedTokenURIAfter.attributes.find((attribute: any) => attribute.trait_type === 'Expired');

      expect(expiredAfter.value).to.equal('Yes');
    })
  });

  describe("Minting on mumbai", function () {
    it.skip("Should allow minting using a proof generated by ark-circom", async function () {
      const newCallDataFromArkCircom = [["0x089e5850e432d76f949cedc26527a7fb093194dd4026d5efb07c8ce6093fa977", "0x0154b01b5698e6249638be776d3641392cf89a5ad687beb2932c0ccf33f271d4"], [["0x2692dbce207361b048e6eff874fdc5d50433baa546fa754348a87373710044c0", "0x1db8ddab0dc204d41728efc05d2dae690bebb782b6088d92dda23a87b6bed0a2"], ["0x106be642690f0fe3562d139ed09498d979c8b35ecfb04e5a49422015cafa2705", "0x0b133e53cd0b4944ce2d34652488a16d1a020905dc1972ccc883d364dd3bb4ee"]], ["0x09eda5d551b150364ecb3efb432e4568b2be8f83c2db1dd1e1285c45a428b32b", "0x008ee9e870e5416849b3c94b8b9e4759580659f5a6535652d0a6634df23db2f5"], ["0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000000000000000000000000000", "0x000000000000000000000000000000006df9dd0914f215fafa1513e51ac9f1e2", "0x00000000000000000000000000000000000000000000093e703cd030e286890e", "0x0000000000000000000000000000000000000000000004770a914f3ae4e1288b", "0x000000000000000000000000000000000000000000000bf7e8ecb4e9609a489d", "0x00000000000000000000000000000000000000000000035762de41038bc2dcf1", "0x00000000000000000000000000000000000000000000050442c4055d62e9c4af", "0x0000000000000000000000000000000000000000000004db2bdc79a477a0fce0", "0x000000000000000000000000000000000000000000000acdbf649c76ec3df9ad", "0x000000000000000000000000000000000000000000000aaa0e6798ee3694f5ca", "0x000000000000000000000000000000000000000000000a1eaac37f80dd5e2879", "0x00000000000000000000000000000000000000000000033e063fba83c27efbce", "0x00000000000000000000000000000000000000000000045b9b05cab95025b000", "0x000000000000000000000000e6e4b6a802f2e0aee5676f6010e0af5c9cdd0a50"]];
      // const callDataFromArkCircomGeneratedInTest = [ [ '0x07a378ec2b5bafc15a21fb9c549ba2554a4ef22cfca3d835f44d270f547d0913', '0x089bb81fb68200ef64652ada5edf71a98dcc8a931a54162b03b61647acbae1fe' ], [ [ '0x2127ae75494aed0c384567cc890639d7609040373d0a549e665a26a39b264449', '0x2f0ea6c99648171b7e166086108131c9402f9c5ac4a3759705a9c9217852e328' ], [ '0x04efcb825be258573ffe8c9149dd2b040ea3b8a9fa3dfa1c57a87b11c20c21ec', '0x2b500aece0e5a5a64a5c7262ec379efc1a23f4e46d968aebd42337642ea2bd3e' ] ], [ '0x1964dc2231bcd1e0de363c3d2a790346b7e634b5878498ce6e8db0ac972b8125', '0x0d94cd74a89b0ed777bb309ce960191acd23d5e9c5f418722d03f80944c5e3ed' ], [ '0x000000000000000000544e45524f4c4600000000000000000000000000000000', '0x0000000000000000000000000000000000000000000000000000000000000000', '0x0000000000000000000000000000000000000000000000000000000000000000', '0x000000000000000000000000000000000df267467de87516584863641a75504b', '0x00000000000000000000000000000000000000000000084c754a8650038f4c82', '0x000000000000000000000000000000000000000000000d38447935bb72a5193c', '0x000000000000000000000000000000000000000000000cac133b01f78ab24970', '0x0000000000000000000000000000000000000000000006064295cda88310ce6e', '0x000000000000000000000000000000000000000000001026cd8776cbd52df4b0', '0x000000000000000000000000000000000000000000000d4748d254334ce92b36', '0x0000000000000000000000000000000000000000000005c1b0ba7159834b0bf1', '0x00000000000000000000000000000000000000000000029d91f03395b916792a', '0x000000000000000000000000000000000000000000000bcfbb30f8ea70a224df', '0x00000000000000000000000000000000000000000000003dcd943c93e565aa3e', '0x0000000000000000000000000000000000000000000009e8ce7916ab0fb0b000', '0x000000000000000000000000ede0fa5a7b196f512204f286666e5ec03e1005d2' ] ];

      const proofOfPassportOnMumbaiAddress = '0x7D459347d092D35f043f73021f06c19f834f8c3E';
      const proofOfPassportOnMumbai = await ethers.getContractAt('ProofOfPassport', proofOfPassportOnMumbaiAddress);
      try {
        const tx = await proofOfPassportOnMumbai.mint(...newCallDataFromArkCircom as any);
        console.log('txHash', tx.hash);
        const receipt = await tx.wait();
        console.log('receipt', receipt)
        expect(receipt?.status).to.equal(1);
      } catch (error) {
        console.error(error);
        expect(true).to.equal(false);
      }
    });

    it.skip("Should allow minting using lambda function", async function () {
      const proofOfPassportOnMumbaiAddress = '0x0AAd39A080129763c8E1e2E9DC44E777DB0362a3';
      const provider = new ethers.JsonRpcProvider('https://polygon-mumbai-bor.publicnode.com');
      const proofOfPassportOnMumbai = await ethers.getContractAt('ProofOfPassport', proofOfPassportOnMumbaiAddress);

      try {
        const transactionRequest = await proofOfPassportOnMumbai
          .mint.populateTransaction(...callData);

        console.log('transactionRequest', transactionRequest);

        const apiEndpoint = process.env.AWS_ENDPOINT;
        if (!apiEndpoint) {
          throw new Error('AWS_ENDPOINT env variable is not set');
        }
        const response = await axios.post(apiEndpoint, {
          chain: "mumbai",
          tx_data: transactionRequest
        });
        console.log('response status', response.status)
        console.log('response data', response.data)
        const receipt = await provider.waitForTransaction(response.data.hash);
        console.log('receipt', receipt)
      } catch (err) {
        console.log('err', err);
      }
    });
  })
});
