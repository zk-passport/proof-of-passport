#!/bin/bash

# Check if the first argument is "app-only"
if [ "$1" == "app-only" ]; then
    echo "Building only for the app"
    APP_ONLY=1
else
    APP_ONLY=0
fi

mkdir -p build
cd build    
if [ ! -f powersOfTau28_hez_final_20.ptau ]; then
    echo "Download power of tau...."
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau
    echo "Finished download!"
else 
    echo "Powers of tau file already downloaded... Skip download action!"
fi
cd ..

echo "compiling circuit"
circom circuits/proof_of_passport.circom --r1cs --sym --wasm --output build

mkdir -p ../app/ark-circom-passport/passport/
cp build/proof_of_passport.r1cs ../app/ark-circom-passport/passport/
cp build/proof_of_passport_js/proof_of_passport.wasm ../app/ark-circom-passport/passport/
echo "copied proof_of_passport.r1cs and proof_of_passport.wasm to ark-circom-passport"
echo "file sizes:"
echo "Size of proof_of_passport.r1cs: $(wc -c <../app/ark-circom-passport/passport/proof_of_passport.r1cs) bytes"
echo "Size of proof_of_passport.wasm: $(wc -c <../app/ark-circom-passport/passport/proof_of_passport.wasm) bytes"

# If APP_ONLY is 1, exit the script here
if [ $APP_ONLY -eq 1 ]; then
    exit 0
fi

echo "building zkey"
yarn snarkjs groth16 setup build/proof_of_passport.r1cs build/powersOfTau28_hez_final_20.ptau build/proof_of_passport.zkey

echo "building vkey"
echo "test random" | yarn snarkjs zkey contribute build/proof_of_passport.zkey build/proof_of_passport_final.zkey
yarn snarkjs zkey export verificationkey build/proof_of_passport_final.zkey build/proof_of_passport_vkey.json

yarn snarkjs zkey export solidityverifier build/proof_of_passport_final.zkey build/Verifier.sol
cp build/Verifier.sol ../contracts/contracts/Verifier.sol
co build/proof_of_passport_final.zkey ../app/ark-circom-passport/passport/
echo "copied Verifier.sol to contracts and proof_of_passport_final.zkey to ark-circom-passport"
