mkdir -p ../circuits/build
cd ../circuits/build
if [ -f "proof_of_passport_final.arkzkey" ]; then
    echo "found previous proof_of_passport_final.arkzkey, deleting it"
    rm "proof_of_passport_final.arkzkey"
fi
echo "downloading proof_of_passport_final.arkzkey to /circuits/build/"

# parse the arkzkey url in deployments/arkzkeyUrl.json
ZKEY_URL=$(grep "zkeyUrl" ../../app/deployments/arkzkeyUrl.json | awk -F'"' '{print $4}')
wget -O proof_of_passport_final.arkzkey "$ZKEY_URL"