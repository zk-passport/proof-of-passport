# Proof of Passport

Monorepo for the Proof of Passport protocol.

Proof of Passport lets users scan the NFC chip in their government-issued passport.
If the signature is valid, the user can generate a proof that can be verified onchain.
We are using that proof to mint them a Soulbound Token (SBT) they can use to show that they indeed hold
an official passport.
Users can also selectively disclose personal info like their nationality or their date of birth.

### Subdirectories

- `app`: Mobile app
- `circuits`: Circom circuits
- `contracts`: Solidity contracts

### Roadmap

- ✅ Basic passport verifier circuit
- 🚧 Optimization
- ✅ Selective disclosure
- ✅ Basic react native frontend
- ✅ Passport verification pipeline, android
- 🚧 Passport verification pipeline, iOS
- 🚧 Contracts
- 🚧 On-chain registry of CSCA pubkeys based on the official ICAO masterlist