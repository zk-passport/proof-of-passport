// One-off: deploy the 2.14.0 hub implementation as a SINGLE transaction,
// linked against libraries already on mainnet and byte-verified against this
// compile. The `upgrade` task redeploys all 7 libraries on every invocation and
// races forno's load-balanced nonce view; this avoids both.
import hre from "hardhat";

const LIBRARIES = {
  CustomVerifier: "0x5c42Fec75F370BA58ce40fEEEc13ea44521CedB8",
  OutputFormatterLib: "0xB25435fe45D57fFcC32395078AdFAfB3DD6a50fa",
  ProofVerifierLib: "0x40B30f3eb1A1aaE5aF9288510D61DF7a39e9b43e",
  RegisterProofVerifierLib: "0x55eA8AA855612FA618e585511ccD6E186F38069d",
  DscProofVerifierLib: "0x5f93fDf891Db6Ef771A6F05b24A99d0BA16c41e9",
  RootCheckLib: "0xef367dCb63205971051FAdD1a1A16B475367D365",
  OfacCheckLib: "0x21095DBFf1c672e16589324Ab652555f2FE83150",
};

async function main() {
  const [signer] = await hre.ethers.getSigners();
  const net = await hre.ethers.provider.getNetwork();
  console.log("chainId :", net.chainId.toString());
  console.log("deployer:", await signer.getAddress());
  console.log("nonce   :", await hre.ethers.provider.getTransactionCount(await signer.getAddress()));

  const F = await hre.ethers.getContractFactory("IdentityVerificationHubImplV2", {
    libraries: LIBRARIES,
    signer,
  });
  const impl = await F.deploy();
  const tx = impl.deploymentTransaction();
  console.log("tx hash :", tx?.hash);
  await impl.waitForDeployment();
  console.log("IMPL    :", await impl.getAddress());
}

main().catch((e) => { console.error(e); process.exit(1); });
