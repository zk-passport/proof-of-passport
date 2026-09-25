# Contract Upgrade Guide

## Quick Start

### 1. Update Your Contract

```solidity
// Update version in NatSpec
* @custom:version 2.13.0

// Update reinitializer modifier (increment by 1)
function initialize(...) external reinitializer(13) {
    // Add any new initialization logic
}
```

### 2. Run the Upgrade Script

```bash
cd contracts
npx hardhat upgrade --contract IdentityVerificationHub --network celo --changelog "Added feature X"
```

### 3. Approve in Safe

The script outputs instructions to submit to the Safe multisig. Once 3/5 signers approve, execute the transaction.

---

## Governance Roles

| Role              | Threshold | Purpose                              |
| ----------------- | --------- | ------------------------------------ |
| `SECURITY_ROLE`   | 3/5       | Contract upgrades, role management   |
| `OPERATIONS_ROLE` | 2/5       | CSCA root updates, OFAC list updates |

---

## Detailed Workflow

### Step 1: Modify the Contract

1. Make your code changes
2. Update `@custom:version` in the contract's NatSpec comment
3. Increment the `reinitializer(N)` modifier (e.g., `reinitializer(12)` → `reinitializer(13)`)
4. Add any new storage fields **at the end** of the storage struct

**Example:**

```solidity
/**
 * @title IdentityVerificationHubImplV2
 * @custom:version 2.13.0
 */
contract IdentityVerificationHubImplV2 is ImplRoot {

    struct HubStorage {
        // Existing fields...
        uint256 newField;  // Add new fields at the end only
    }

    function initialize(...) external reinitializer(13) {
        // Initialize new fields if needed
        HubStorage storage $ = _getHubStorage();
        $.newField = defaultValue;
    }
}
```

### Step 2: Run the Upgrade Script

```bash
npx hardhat upgrade --contract <ContractName> --network <network> --changelog "Description"
```

**Options:**

- `--contract` - Contract name (e.g., `IdentityVerificationHub`)
- `--network` - Target network (`celo`, `sepolia`, `localhost`)
- `--changelog` - Brief description of changes
- `--prepare-only` - Deploy implementation without creating Safe proposal

### Step 3: Script Execution

The script automatically:

1. **Validates version** - Ensures `@custom:version` is incremented correctly
2. **Checks reinitializer** - Verifies `reinitializer(N)` matches expected version
3. **Validates storage** - Ensures no breaking storage layout changes
4. **Compiles fresh** - Clears cache to prevent stale bytecode
5. **Compares bytecode** - Warns if implementation hasn't changed
6. **Deploys implementation** - Deploys new implementation contract
7. **Updates registry** - Records deployment in `deployments/registry.json`
8. **Creates git commit & tag** - Auto-commits changes with version tag
9. **Creates Safe proposal** - If you're a signer, auto-proposes to Safe

### Step 4: Multisig Approval

**If you're a Safe signer:**

- Script auto-proposes the transaction
- Other signers approve in Safe UI
- Execute once threshold (3/5) is met

**If you're not a signer:**

- Script outputs transaction data for manual submission
- Copy data to Safe Transaction Builder
- Signers approve and execute

---

## Safety Checks

The upgrade script performs these automatic checks:

| Check                  | What it Does                       | Failure Behavior     |
| ---------------------- | ---------------------------------- | -------------------- |
| Version validation     | Ensures semantic version increment | Blocks upgrade       |
| Reinitializer check    | Verifies modifier matches version  | Blocks upgrade       |
| Storage layout         | Detects breaking storage changes   | Blocks upgrade       |
| Bytecode comparison    | Warns if code unchanged            | Prompts confirmation |
| Safe role verification | Confirms Safe has `SECURITY_ROLE`  | Blocks upgrade       |
| Constructor check      | Flags `_disableInitializers()`     | Prompts confirmation |

---

## Registry Structure

All deployments are tracked in `deployments/registry.json`:

```json
{
  "contracts": {
    "ContractName": {
      "source": "ContractSourceFile",
      "type": "uups-proxy"
    }
  },
  "networks": {
    "celo": {
      "deployments": {
        "ContractName": {
          "proxy": "0x...",
          "currentVersion": "2.12.0",
          "currentImpl": "0x..."
        }
      }
    }
  },
  "versions": {
    "ContractName": {
      "2.12.0": {
        "initializerVersion": 12,
        "changelog": "...",
        "gitTag": "contractname-v2.12.0",
        "deployments": { ... }
      }
    }
  }
}
```

---

## Utility Commands

```bash
# Check current deployment status
npx hardhat upgrade:status --contract IdentityVerificationHub --network celo

# View version history
npx hardhat upgrade:history --contract IdentityVerificationHub
```

---

## Prover Key Config (Hub + KYC Registry)

`IdentityVerificationHubImplV2.registerProverKey` and `IdentityRegistryKycImplV1.registerPubkeyCommitment` both verify a
GCP Confidential Space attestation, and each contract holds its **own** copy of the config that verification depends on:
a GCP root CA pubkey hash and a `PCR0Manager` pointer. This duplication was an accepted design cost (see
`docs/superpowers/specs/2026-08-18-hub-register-prover-key-design.md`) in exchange for the hub not depending on the KYC
registry at runtime. It means every rotation below must touch both contracts, and the two `PCR0Manager` instances must
never be the same one.

### (a) Rotating the root CA hash or PCR0Manager pointer

Both values live independently on each contract. Rotating one and forgetting the other leaves them inconsistent — one
contract keeps verifying against stale config while the other verifies against the new one.

| Config value            | Hub setter                                 | KYC registry setter                  |
| ----------------------- | ------------------------------------------ | ------------------------------------ |
| GCP root CA pubkey hash | `updateProverGCPRootCAPubkeyHash(uint256)` | `updateGCPRootCAPubkeyHash(uint256)` |
| PCR0Manager pointer     | `updateProverPCR0Manager(address)`         | `updatePCR0Manager(address)`         |
| GCP JWT verifier        | `updateProverGCPJWTVerifier(address)`      | `updateGCPJWTVerifier(address)`      |
| Attested TEE address    | `updateProverTEE(address)`                 | `updateTEE(address)`                 |

Every setter above is `onlyRole(SECURITY_ROLE)` and emits an event, so drift between the two contracts is observable
off-chain by diffing the latest event per config value on each contract. When rotating, call the matching pair together
and verify both events landed before considering the rotation done.

### (b) Keep prover and KYC PCR0Manager instances separate

**This is the security-relevant rule, not just tidiness.** `PCR0Manager` is a flat set of approved image digests — it
has no notion of enclave _role_. If the hub's `_pcr0Manager` pointer is ever set to the **same instance** the KYC
registry points at (or prover image digests are added to that shared instance for convenience), then a prover
attestation replayed into `IdentityRegistryKycImplV1.registerPubkeyCommitment` passes the image check. That path has no
length assertion on the decoded value (unlike `GCPJWTHelper.unpackAndDecodeAddress`, which enforces exactly 40 hex
characters), so it would register the prover's address value as a KYC pubkey commitment. Exploiting this still requires
the KYC registry's `_tee` signing key and a commitment preimage, so it's a garbage-write, not an auth bypass — but it
re-introduces exactly the cross-role hazard that keeping `registerProverKey` off the KYC registry was meant to remove
(see the design doc's "Why the hub and not the KYC registry" section).

**Rule:** the hub's `PCR0Manager` instance must contain only prover image digests. The KYC registry's `PCR0Manager`
instance must contain only KYC-attestor image digests. Never point both contracts at the same instance, and never add
prover digests to the KYC registry's instance. Both pointers are independently configurable, so keeping them separate
costs nothing — it just has to be recorded so nobody reaches for the existing instance out of convenience during a
future rotation.

### (c) Post-upgrade config sequence for `registerProverKey`

After deploying the `IdentityVerificationHubImplV2` upgrade that introduces `registerProverKey`, the following four
`SECURITY_ROLE` setters must all be called before the function will succeed:

1. `updateProverGCPJWTVerifier(address)`
2. `updateProverPCR0Manager(address)` — pointing at a **prover-only** `PCR0Manager` instance, per (b)
3. `updateProverGCPRootCAPubkeyHash(uint256)`
4. `updateProverTEE(address)`

This is fail-closed by design: the config guard checked at the top of `registerProverKey` reverts `ProverConfigNotSet`
if any of the four is still at its zero default. A fresh proxy upgrade (no `reinitializer` bump — the ERC-7201
namespace's all-zero defaults are exactly what the guard treats as "not configured yet") will revert on every call until
all four are set, by construction rather than by convention.

### Prerequisite: the prover must already emit a bare 40-character nonce

`unpackAndDecodeAddress` decodes exactly 40 ASCII hex characters and reverts on anything longer, so a prover that puts a
`0x`-prefixed 42-character address in its attestation nonce fails every registration — after the four setters have
succeeded, which makes it look like a contract problem rather than a version-skew one.

So before enabling registration:

1. Deploy the `tee-prover-server` build whose attestation nonce carries the **bare** 40 hex characters, with no `0x`
   prefix.
2. Validate one real attestation end to end against the deployed hub on a testnet, and confirm `ProverKeyRegistered`
   fires with the address you expect.
3. Only then treat `registerProverKey` as enabled in production.

The ordering is one-way: the contract cannot accept the prefixed form without also accepting a 42-character nonce, which
would widen what it decodes. Fixing the producer is the correct side.

### (d) Deploy ordering for prover signature enforcement (v2.15.0)

From v2.15.0, `registerCommitment`, `registerDscKeyCommitment`, and the disclose flow (`verify`, via the signature
embedded in `proofPayload`) **unconditionally** require their 65-byte signature to recover (via
`keccak256(abi.encode(a, b, c, pubSignals))`, raw prehash, no EIP-191 prefix) to a registered prover key. There is no
toggle and no storage change — enforcement is live from the upgrade block, and a relayer still sending placeholder zeros
bricks both the register and disclose flows.

**Adding the `signature` parameter changes both function selectors.** There is no overload: the 3-argument functions
cease to exist at the upgrade block.

| Function                   | v2.14.0 (3-arg) | v2.15.0 (4-arg) |
| -------------------------- | --------------- | --------------- |
| `registerCommitment`       | `0xf2ea431c`    | `0x848cd73b`    |
| `registerDscKeyCommitment` | `0x8322963f`    | `0xed9b4fd7`    |

**The disclose flow breaks the same way for a different reason.** `verifySelfProof(bytes,bytes)` keeps its selector —
the signature rides inside `proofPayload`, whose layout changes from `| 32 bytes attestationId | proofData |` to
`| 32 bytes attestationId | 65 bytes signature | proofData |`. Nothing about the call shape changes, so a version-skewed
call is accepted and only then found to be wrong.

**What it looks like when it happens.** An old-format payload reaching a v2.15.0 hub has the first 65 bytes of its proof
data consumed as a signature, leaving the remainder shifted by 65 bytes. `_decodeInput` strips those bytes, and
`_executeVerificationFlow` hands the shifted remainder to `_decodeVcAndDiscloseProof`, which is a plain
`abi.decode(data, (GenericProofStruct))`. That is evaluated as an argument to `_basicVerification`, so it runs _before_
the body reaches `_verifyProverSignature`. A shifted ABI blob has broken offsets, so the call reverts inside
`abi.decode` — **with no reason string and no custom error at all**, not with `UnauthorizedProverSigner`.

So during a rollout, read the two symptoms in opposite directions:

| Symptom                      | Most likely cause                                                    |
| ---------------------------- | -------------------------------------------------------------------- |
| revert with no reason string | version skew — the relayer is sending the old `proofPayload` layout  |
| `InvalidDataFormat`          | payload shorter than 98 bytes, i.e. no room for the signature at all |
| `UnauthorizedProverSigner`   | a genuine prover-key problem: unregistered, revoked, or wrong signer |

Only the third is about prover keys. Reaching it requires a payload that decoded cleanly, which a shifted one will not.

That makes the relayer and the hub a **mutually exclusive pair** for both flows, and it is why the ordering below is a
cutover rather than a sequence. A relayer sending 4-argument register calldata to the v2.14.0 hub matches no function
and the proxy reverts; a relayer still sending 3-argument calldata after the upgrade reverts the same way; and the
disclose payloads fail in whichever direction the skew runs. There is no ordering of "upgrade the hub" and "deploy the
relayer" in which both are briefly true, so register and disclose are unavailable for the window between the two
transactions. Plan for that window rather than trying to order it away.

**v2.14.0 must be deployed first, and it is the reason this rollout has no unavoidable gap.** `registerProverKey`,
`revokeProverKey` and the four `updateProver…` setters ship in v2.14.0; both deployed hubs are older — celo and
celo-sepolia are each on 2.13.0 — so none of those functions exist on-chain today. Steps 2–5 below cannot be executed
against the currently-deployed hub at all.

v2.14.0 is a drop-in for that purpose: it keeps the 3-argument `registerCommitment` and the pre-signature `proofPayload`
layout, adds no enforcement, and therefore changes nothing the relayer sees. It is the intermediate compatibility
release the cutover would otherwise need built from scratch — upgrading to it costs no downtime, and it is what makes
the prover key registerable _before_ enforcement exists rather than after.

Steps 1–5 are ordinary prerequisites and each must be verified before the next. Steps 6 and 7 are the cutover and should
be executed back to back by the same operator, in a scheduled window, with rollback ready.

1. **Upgrade the hub to v2.14.0** if it is not already there. No format change, no enforcement, no downtime — this
   exists solely to make the prover functions callable.
2. Prover config set on the v2.14.0 hub, per (c) — all four setters, or `registerProverKey` reverts
   `ProverConfigNotSet`.
3. Prover image digests registered in the prover-only `PCR0Manager`, per (b).
4. `tee-prover-server` deployed with the `chain` feature enabled and its bare-nonce build, per the prerequisite above.
5. `registerProverKey` succeeded on-chain — confirm `ProverKeyRegistered` fired for the live enclave's address. Verify
   this **before** the cutover: a hub that enforces signatures with no registered key rejects every register and
   disclose call, and this is the last step that can be validated while the old formats are still live.
6. **Cutover begins.** Upgrade the hub implementation to v2.15.0. Register and disclose are both unavailable from this
   transaction.
7. **Cutover ends.** Deploy relayer + db-relayer with the signature pipeline for **both flows** — the 4-argument
   register calldata and the disclose `proofPayload` carrying its 65-byte signature. Confirm real (non-zero) signatures
   reaching the chain on each, and one successful registration and one successful disclosure. Both flows are restored.

Rolling back mid-cutover means reverting the hub to the previous implementation (see Rollback below), which restores the
3-argument selectors and the old `proofPayload` layout, and therefore the old relayer. Do not roll back the hub after
the new relayer is live without also reverting the relayer.

An earlier revision of this guide placed the relayer deploy before the hub upgrade, on the reasoning that real
signatures should be observed flowing before enforcement went live. That ordering cannot execute. For register, those
signatures can only reach the hub through the 4-argument selector, which does not exist until step 6. For disclose, an
old hub reads the 65 signature bytes as the first bytes of proof data and fails proof verification. Observing signatures
pre-upgrade would require an intermediate hub release that accepts them and ignores them — that release does not exist,
since both the parameter and its enforcement ship together in v2.15.0. If a zero-downtime rollout is required, that
intermediate release is the way to get it, and it must be built and deployed first.

Keys are ephemeral per enclave boot: every reboot mints a new key that must be registered before its proofs are
accepted, and `revokeProverKey` (SECURITY_ROLE) retires a compromised one immediately — revoking the only registered key
halts the register and disclose flows until a fresh attestation registers a replacement.

---

## Rollback

If issues occur after upgrade:

1. Deploy the previous implementation version
2. Create Safe transaction calling `upgradeToAndCall(previousImpl, "0x")`
3. Execute with 3/5 multisig approval

---

## Environment Setup

Required in `.env`:

```bash
CELO_RPC_URL=https://forno.celo.org
PRIVATE_KEY=0x...  # Deployer wallet (needs ETH for gas)
```

Optional for contract verification:

```bash
CELOSCAN_API_KEY=...
ETHERSCAN_API_KEY=...
```

---

## Troubleshooting

| Issue                         | Solution                                  |
| ----------------------------- | ----------------------------------------- |
| "Version matches current"     | Update `@custom:version` in contract      |
| "Reinitializer mismatch"      | Update `reinitializer(N)` to next version |
| "Storage layout incompatible" | Don't remove/reorder storage variables    |
| "Safe not indexed"            | Submit manually via Safe UI               |
| "Bytecode unchanged"          | Ensure you saved contract changes         |
