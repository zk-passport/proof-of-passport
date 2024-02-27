
ARCHITECTURE="aarch64-apple-ios" # or "x86_64-apple-ios" for "x86_64", "aarch64-apple-ios-sim" for simulator
LIB_DIR="release" # or "debug"
PROJECT_DIR=$(pwd)

# Assert we're in the /app dir
if [[ ! -d "mopro-ffi" || ! -d "mopro-core" || ! -d "ark-zkey" ]]; then
    echo -e "${RED}Error: This script must be run from the /app dir that contains mopro-ffi, mopro-core and ark-zkey folders.${DEFAULT}"
    exit 1
fi

# Check for target support
check_target_support() {
    rustup target list | grep installed | grep -q "$1"
}

# Install arkzkey-util binary in ark-zkey
cd ark-zkey
echo "[ark-zkey] Installing arkzkey-util..."
if ! command -v arkzkey-util &> /dev/null
then
    cargo install --bin arkzkey-util --path .
else
    echo "arkzkey-util already installed, skipping."
fi
cd ..

# check target is installed
if ! check_target_support $ARCHITECTURE; then
    rustup target add $ARCHITECTURE
else
    echo "Target $ARCHITECTURE already installed, skipping."
fi


# generate ark-zkey
cd ../circuits/build
# arkzkey-util proof_of_passport_final.zkey
# echo "arkzkey file generation done, arkzkey file is in $(pwd)/proof_of_passport_final.arkzkey"

cd ../../app/mopro-core
cargo build --release --features dylib

cd ../mopro-ffi
echo "Building mopro-ffi static library..."
cargo build --release --target ${ARCHITECTURE} --features dylib
echo "Copying:"
cp target/${ARCHITECTURE}/${LIB_DIR}/libmopro_ffi.a ../ios/MoproKit/Libs/
cp ${PROJECT_DIR}/mopro-core/target/${ARCHITECTURE}/${LIB_DIR}/proof_of_passport.dylib ../ios/MoproKit/Libs/

# cp target/${ARCHITECTURE}/${LIB_DIR}/libmopro_ffi.dylib ../ios/MoproKit/Libs/
echo "copied libmopro_ffi.a to ios/Moprokit/Libs/"
# echo "copied libmopro_ffi.dylib to ios/Moprokit/Libs/"

# TODO: if functions signatures change, we have to rebuild the bindings by adapting theses lines:
cd ..
# Install uniffi-bindgen binary in mopro-ffi
echo "[ffi] Installing uniffi-bindgen..."
if ! command -v uniffi-bindgen &> /dev/null
then
    cargo install --bin uniffi-bindgen --path .
else
    echo "uniffi-bindgen already installed, skipping."
fi
echo "Updating mopro-ffi bindings and library..."
uniffi-bindgen generate mopro-ffi/src/mopro.udl --language swift --out-dir SwiftBindings
cp SwiftBindings/moproFFI.h ios/MoproKit/Include/
cp SwiftBindings/mopro.swift ios/MoproKit/Bindings/
cp SwiftBindings/moproFFI.modulemap ios/MoproKit/Resources/

# Fix dynamic lib install paths
# NOTE: Xcode might already do this for us
install_name_tool -id @rpath/proof_of_passport.dylib ${PROJECT_DIR}/ios/MoproKit/Libs/proof_of_passport.dylib
codesign -f -s "${APPLE_SIGNING_IDENTITY}" ${PROJECT_DIR}/ios/MoproKit/Libs/proof_of_passport.dylib
