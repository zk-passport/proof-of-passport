
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
circom circuits/merkle_tree/only_tree.circom --r1cs --sym --wasm --output build

echo "building zkey"
yarn snarkjs groth16 setup build/only_tree.r1cs build/powersOfTau28_hez_final_20.ptau build/only_tree.zkey

echo "building vkey"
echo "test random" | yarn snarkjs zkey contribute build/only_tree.zkey build/only_tree_final.zkey
yarn snarkjs zkey export verificationkey build/only_tree_final.zkey build/only_tree_verification_key.json