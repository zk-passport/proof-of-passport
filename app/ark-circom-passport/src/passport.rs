use ark_circom::{ethereum, CircomBuilder, CircomConfig, circom::CircomReduction, WitnessCalculator};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof};
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_groth16::{ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_bn254::{Fr};

use num_bigint::{BigInt, Sign, ToBigInt};
extern crate hex;
use hex::decode;

type GrothBn = Groth16<Bn254>;

extern crate jni;
use jni::objects::{JClass, JObject, JValue, JString};
use jni::JNIEnv;
use jni::sys::jstring;

use log::Level;
use android_logger::Config;

extern crate serde;
extern crate serde_json;
use serde_json::json;
#[macro_use]
extern crate serde_derive;

use std::{
    collections::HashMap,
    time::Instant,
    convert::TryInto,
    sync::Mutex,
    {os::raw::c_int, io::BufReader},
    fs::File,
    path::Path
};

use wasmer::{Module, Store};
use once_cell::sync::{Lazy, OnceCell};

mod zkey;
pub use zkey::{read_zkey, read_zkey_from_include_bytes};
use ark_zkey::{read_arkzkey, read_arkzkey_from_bytes};

const WASM: &[u8] = include_bytes!("../passport/proof_of_passport.wasm");
static WITNESS_CALCULATOR: OnceCell<Mutex<WitnessCalculator>> = OnceCell::new();

#[must_use]
pub fn witness_calculator() -> &'static Mutex<WitnessCalculator> {
    WITNESS_CALCULATOR.get_or_init(|| {
        let store = Store::default();
        let module = Module::from_binary(&store, WASM).expect("WASM should be valid");
        let result =
            WitnessCalculator::from_module(module).expect("Failed to create WitnessCalculator");
        Mutex::new(result)
    })
}

#[cfg(feature = "download_arkzkey")]
#[must_use]
pub fn load_zkey(zkey_path_str: &str) -> Result<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> {
    let (serialized_proving_key, serialized_constraint_matrices) = read_arkzkey(zkey_path_str).expect("Failed to read zkey from file");
    // Formatting for ark-circom API here as it's not done in mopro rn 
    let proving_key: ProvingKey<Bn254> = serialized_proving_key.0;
    let constraint_matrices: ConstraintMatrices<Fr> = ConstraintMatrices {
        num_instance_variables: serialized_constraint_matrices.num_instance_variables,
        num_witness_variables: serialized_constraint_matrices.num_witness_variables,
        num_constraints: serialized_constraint_matrices.num_constraints,
        a_num_non_zero: serialized_constraint_matrices.a_num_non_zero,
        b_num_non_zero: serialized_constraint_matrices.b_num_non_zero,
        c_num_non_zero: serialized_constraint_matrices.c_num_non_zero,
        a: serialized_constraint_matrices.a.data,
        b: serialized_constraint_matrices.b.data,
        c: serialized_constraint_matrices.c.data,
    };
    
    Ok((proving_key, constraint_matrices))
}

#[cfg(not(feature = "download_arkzkey"))]
#[must_use]
pub fn load_zkey(_zkey_path_str: &str) -> Result<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> {
    let file_bytes: &'static [u8] = include_bytes!("../passport/proof_of_passport_final.arkzkey");
    log::error!("PROOF OF PASSPORT ---- arkzkey size: {}", file_bytes.len());
    let (params, matrices) = read_arkzkey_from_bytes(file_bytes).unwrap();
    Ok((params, matrices))
}

#[no_mangle]
pub extern "C" fn Java_io_tradle_nfc_RNPassportReaderModule_provePassport(
    env: JNIEnv,
    _: JClass,
    mrz: JObject,
    reveal_bitmap: JObject,
    data_hashes: JObject,
    datahashes_padded_length: JString,
    e_content_bytes: JObject,
    signature: JObject,
    pubkey: JObject,
    address: JString,
    zkeypath: JString,
) -> jstring {
    match run_proof(
        mrz,
        reveal_bitmap,
        data_hashes,
        datahashes_padded_length,
        e_content_bytes,
        signature,
        pubkey,
        address,
        zkeypath,
        env
    ) {
        Ok(output) => output,
        Err(_) => env.new_string("error").expect("Couldn't create java string!").into_inner(),
    }
}

fn run_proof(
    mrz: JObject,
    reveal_bitmap: JObject,
    data_hashes: JObject,
    datahashes_padded_length: JString,
    e_content_bytes: JObject,
    signature: JObject,
    pubkey: JObject,
    address: JString,
    zkeypath: JString,
    env: JNIEnv
) -> Result<jstring, Box<dyn std::error::Error>> {
    android_logger::init_once(Config::default().with_min_level(Level::Trace));
    let mut rng = thread_rng();
    let rng = &mut rng;
    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    log::error!("PROOF OF PASSPORT ---- formatting inputs...");
    let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();

    insert_collection(&env, &mut inputs, "mrz", mrz)?;
    insert_collection(&env, &mut inputs, "reveal_bitmap", reveal_bitmap)?;
    insert_collection(&env, &mut inputs, "dataHashes", data_hashes)?;
    insert_collection(&env, &mut inputs, "eContentBytes", e_content_bytes)?;
    insert_collection(&env, &mut inputs, "signature", signature)?;
    insert_collection(&env, &mut inputs, "pubkey", pubkey)?;

    let address_str: String = env.get_string(address)?.into();
    let address_bigint = BigInt::from_bytes_be(Sign::Plus, &decode(&address_str[2..])?);
    inputs.insert("address".to_string(), vec![address_bigint]);
    log::error!("PROOF OF PASSPORT ---- address_str {:?}", address_str);

    let datahashes_padded_length_str: String = env.get_string(datahashes_padded_length)?.into();
    let datahashes_padded_length_i32 = datahashes_padded_length_str.parse::<i32>().expect("Failed to parse datahashes_padded_length to i32");
    let datahashes_padded_length_bigint = BigInt::from(datahashes_padded_length_i32);
    inputs.insert("datahashes_padded_length".to_string(), vec![datahashes_padded_length_bigint]);
    log::error!("PROOF OF PASSPORT ---- datahashes_padded_length_str {:?}", datahashes_padded_length_str);

    println!("generating witness...");
    let now = Instant::now();
    let full_assignment = witness_calculator()
        .lock()
        .expect("Failed to lock witness calculator")
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(|e| e.to_string())?;
    log::error!("PROOF OF PASSPORT ---- Witness generation took. Took: {:?}", now.elapsed());

    log::error!("PROOF OF PASSPORT ---- loading arkzkey...");
    let now = Instant::now();
    let zkey_path_jstring = env.get_string(zkeypath).expect("Couldn't get zkey path string");
    let zkey_path_str = zkey_path_jstring.to_str().unwrap();
    let zkey = load_zkey(zkey_path_str)?;
    log::error!("PROOF OF PASSPORT ---- arkzkey loaded. Took: {:?}", now.elapsed());
    println!("Loading arkzkey took: {:.2?}", now.elapsed());

    let now = Instant::now();
    let public_inputs = full_assignment.as_slice()[1..zkey.1.num_instance_variables].to_vec();
    let ark_proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
        full_assignment.as_slice(),
    );

    let proof = ark_proof.map_err(|e| e.to_string())?;

    log::error!("PROOF OF PASSPORT ---- proof: {:?}", proof);
    log::error!("PROOF OF PASSPORT ---- public_inputs: {:?}", public_inputs);
    log::error!("PROOF OF PASSPORT ---- proof done. Took: {:?}", now.elapsed());
    println!("proof {:?}", proof);
    println!("public_inputs {:?}", public_inputs);
    println!("proof generation took: {:.2?}", now.elapsed());

    // previous way of verifying proof
    // let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
    // let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    // println!("Proof verified. Took: {:?}", now.elapsed());
    // log::error!("PROOF OF PASSPORT ---- proof verified. Took: {:?}", now.elapsed());
    // assert!(verified);

    let converted_inputs: ethereum::Inputs = public_inputs.as_slice().into();
    let inputs_str: Vec<String> = converted_inputs.0.iter().map(|value| format!("{}", value)).collect();
    let serialized_inputs = serde_json::to_string(&inputs_str).unwrap();
    log::error!("PROOF OF PASSPORT ---- Serialized inputs: {:?}", serialized_inputs);

    let proof_str = proof_to_proof_str(&proof);
    let serialized_proof = serde_json::to_string(&proof_str).unwrap();

    log::error!("PROOF OF PASSPORT ---- Serialized proof: {:?}", serialized_proof);

    let combined = json!({
        "serialized_proof": serialized_proof,
        "serialized_inputs": serialized_inputs
    });
    
    let combined_str = combined.to_string();
    let output = env.new_string(combined_str).expect("Couldn't create java string!");

    Ok(output.into_inner())
}

fn insert_collection(env: &JNIEnv, inputs: &mut HashMap<String, Vec<num_bigint::BigInt>>, key: &str, object: JObject) -> Result<(), Box<dyn std::error::Error>> {
    let vec: Vec<String> = java_arraylist_to_rust_vec(env, object)?;
    log::error!("PROOF OF PASSPORT ---- {} {:?}", key, vec);

    let parsed_data: Vec<num_bigint::BigInt> = vec.iter()
        .filter_map(|s| s.parse::<u128>().ok().and_then(|num| num.to_bigint()))
        .collect();
    inputs.insert(key.to_string(), parsed_data);
    Ok(())
}

fn java_arraylist_to_rust_vec(env: &JNIEnv, java_list: JObject) -> Result<Vec<String>, jni::errors::Error> {
    let size = env.call_method(java_list, "size", "()I", &[])?.i()? as i32;
    let mut vec = Vec::with_capacity(size.try_into().unwrap());

    for i in 0..size {
        let java_string = env.call_method(java_list, "get", "(I)Ljava/lang/Object;", &[JValue::from(i)])?.l()?;
        let rust_string: String = env.get_string(java_string.into())?.into();
        vec.push(rust_string);
    }

    Ok(vec)
}

#[derive(Debug)]
#[derive(Serialize)]
struct ProofStr {
    a: (String, String),
    b: ((String, String), (String, String)),
    c: (String, String),
}

fn proof_to_proof_str(proof: &Proof<Bn254>) -> ProofStr {
    let a_xy = proof.a.xy().unwrap();
    let b_xy = proof.b.xy().unwrap();
    let c_xy = proof.c.xy().unwrap();

    let b_c0_c0 = b_xy.0.c0.to_string();
    let b_c0_c1 = b_xy.0.c1.to_string();
    let b_c1_c0 = b_xy.1.c0.to_string();
    let b_c1_c1 = b_xy.1.c1.to_string();

    ProofStr {
        a: (a_xy.0.to_string(), a_xy.1.to_string()),
        b: ((b_c0_c0, b_c0_c1), (b_c1_c0, b_c1_c1)),
        c: (c_xy.0.to_string(), c_xy.1.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ethers::{
        contract::ContractError,
        prelude::abigen,
        providers::{Http, Middleware, Provider},
        utils::Anvil,
    };
    use std::{
        error::Error,
        fs::File,
        sync::{Arc, Mutex},
        collections::HashMap
    };
    use wasmer::{Module, Store};

    use ark_circom::{
        circom::CircomReduction,
        WitnessCalculator
    };
    use once_cell::sync::{Lazy, OnceCell};
    use ark_groth16::{Groth16, ProvingKey};
    use ark_relations::r1cs::ConstraintMatrices;
    use ark_ff::UniformRand;
    use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
    use num_bigint::ToBigInt;
    use ark_zkey::read_arkzkey_from_bytes; //SerializableConstraintMatrices

    
    // We need to implement the conversion from the Ark-Circom's internal Ethereum types to
    // the ones expected by the abigen'd types. Could we maybe provide a convenience
    // macro for these, given that there's room for implementation error?
    abigen!(Groth16Verifier, "./artifacts/verifier_artifact.json");
    use groth_16_verifier::{G1Point, G2Point, Proof as EthProof, VerifyingKey as Groth16VerifyingKey};

    impl From<ethereum::G1> for G1Point {
        fn from(src: ethereum::G1) -> Self {
            Self { x: src.x, y: src.y }
        }
    }

    impl From<ethereum::G2> for G2Point {
        fn from(src: ethereum::G2) -> Self {
            // We should use the `.as_tuple()` method which handles converting
            // the G2 elements to have the second limb first
            let src = src.as_tuple();
            Self { x: src.0, y: src.1 }
        }
    }
    impl From<ethereum::Proof> for EthProof {
        fn from(src: ethereum::Proof) -> Self {
            Self {
                a: src.a.into(),
                b: src.b.into(),
                c: src.c.into(),
            }
        }
    }
    impl From<ethereum::VerifyingKey> for Groth16VerifyingKey {
        fn from(src: ethereum::VerifyingKey) -> Self {
            Self {
                alfa_1: src.alpha1.into(),
                beta_2: src.beta2.into(),
                gamma_2: src.gamma2.into(),
                delta_2: src.delta2.into(),
                ic: src.ic.into_iter().map(|i| i.into()).collect(),
            }
        }
    }

    impl<M: Middleware> Groth16Verifier<M> {
        async fn check_proof<
            I: Into<ethereum::Inputs>,
            P: Into<ethereum::Proof>,
            VK: Into<ethereum::VerifyingKey>,
        >(
            &self,
            proof: P,
            vk: VK,
            inputs: I,
        ) -> Result<bool, ContractError<M>> {
            // convert into the expected format by the contract
            let proof = proof.into().into();
            let vk = vk.into().into();
            let inputs = inputs.into().0;
            println!("inputs in gorth16 verifier: {:?}", &inputs);

            // query the contract
            let res = self.verify(inputs, proof, vk).call().await?;

            Ok(res)
        }
    }

    const WASM: &[u8] = include_bytes!("../passport/proof_of_passport.wasm");

    static WITNESS_CALCULATOR: OnceCell<Mutex<WitnessCalculator>> = OnceCell::new();

    #[cfg(not(feature = "dylib"))]
    #[must_use]
    pub fn witness_calculator() -> &'static Mutex<WitnessCalculator> {
        WITNESS_CALCULATOR.get_or_init(|| {
            let store = Store::default();
            let module = Module::from_binary(&store, WASM).expect("WASM should be valid");
            let result =
                WitnessCalculator::from_module(module).expect("Failed to create WitnessCalculator");
            Mutex::new(result)
        })
    }

    const ARKZKEY_BYTES: &[u8] = include_bytes!("../passport/proof_of_passport_final.arkzkey");

    static ARKZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
        //let mut reader = Cursor::new(ARKZKEY_BYTES);
        // TODO: Use reader? More flexible; unclear if perf diff
        read_arkzkey_from_bytes(ARKZKEY_BYTES).expect("Failed to read arkzkey")
    });

    // Experimental
    #[must_use]
    pub fn arkzkey() -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
        &ARKZKEY
    }

    fn parse_and_insert(hash_map: &mut HashMap<String, Vec<BigInt>>, key: &str, data: Vec<&str>) {
        let parsed_data: Vec<BigInt> = data.into_iter()
            .filter_map(|s| s.parse::<u128>().ok().and_then(|num| num.to_bigint()))
            .collect();
        hash_map.insert(key.to_string(), parsed_data);
    }
    
    #[tokio::test]
    async fn test_proof() -> Result<(), Box<dyn Error>> {
        let mut rng = thread_rng();
        let rng = &mut rng;
        let r = ark_bn254::Fr::rand(rng);
        let s = ark_bn254::Fr::rand(rng);

        let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
        let values = inputs.entry("a".to_string()).or_insert_with(Vec::new);
        values.push(3.into());

        let mrz_vec: Vec<String> = vec![ "97", "91", "95", "31", "88", "80", "60", "70", "82", "65", "68", "85", "80", "79", "78", "84", "60", "60", "65", "76", "80", "72", "79", "78", "83", "69", "60", "72", "85", "71", "85", "69", "83", "60", "65", "76", "66", "69", "82", "84", "60", "60", "60", "60", "60", "60", "60", "60", "60", "50", "52", "72", "66", "56", "49", "56", "51", "50", "52", "70", "82", "65", "48", "52", "48", "50", "49", "49", "49", "77", "51", "49", "49", "49", "49", "49", "53", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "48", "50"].iter().map(|&s| s.to_string()).collect();
        let reveal_bitmap_vec: Vec<String> = vec![ "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1"].iter().map(|&s| s.to_string()).collect();
        let data_hashes_vec: Vec<String> = vec![ "48", "130", "1", "37", "2", "1", "0", "48", "11", "6", "9", "96", "134", "72", "1", "101", "3", "4", "2", "1", "48", "130", "1", "17", "48", "37", "2", "1", "1", "4", "32", "176", "223", "31", "133", "108", "84", "158", "102", "70", "11", "165", "175", "196", "12", "201", "130", "25", "131", "46", "125", "156", "194", "28", "23", "55", "133", "157", "164", "135", "136", "220", "78", "48", "37", "2", "1", "2", "4", "32", "190", "82", "180", "235", "222", "33", "79", "50", "152", "136", "142", "35", "116", "224", "6", "242", "156", "141", "128", "248", "10", "61", "98", "86", "248", "45", "207", "210", "90", "232", "175", "38", "48", "37", "2", "1", "3", "4", "32", "0", "194", "104", "108", "237", "246", "97", "230", "116", "198", "69", "110", "26", "87", "17", "89", "110", "199", "108", "250", "36", "21", "39", "87", "110", "102", "250", "213", "174", "131", "171", "174", "48", "37", "2", "1", "11", "4", "32", "136", "155", "87", "144", "111", "15", "152", "127", "85", "25", "154", "81", "20", "58", "51", "75", "193", "116", "234", "0", "60", "30", "29", "30", "183", "141", "72", "247", "255", "203", "100", "124", "48", "37", "2", "1", "12", "4", "32", "41", "234", "106", "78", "31", "11", "114", "137", "237", "17", "92", "71", "134", "47", "62", "78", "189", "233", "201", "214", "53", "4", "47", "189", "201", "133", "6", "121", "34", "131", "64", "142", "48", "37", "2", "1", "13", "4", "32", "91", "222", "210", "193", "62", "222", "104", "82", "36", "41", "138", "253", "70", "15", "148", "208", "156", "45", "105", "171", "241", "195", "185", "43", "217", "162", "146", "201", "222", "89", "238", "38", "48", "37", "2", "1", "14", "4", "32", "76", "123", "216", "13", "51", "227", "72", "245", "59", "193", "238", "166", "103", "49", "23", "164", "171", "188", "194", "197", "156", "187", "249", "28", "198", "95", "69", "15", "182", "56", "54", "38", "128", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9", "72"].iter().map(|&s| s.to_string()).collect();
        let datahashes_padded_length_str: String = "320".to_string();
        let e_content_bytes_vec: Vec<String> = vec![ "49", "102", "48", "21", "6", "9", "42", "134", "72", "134", "247", "13", "1", "9", "3", "49", "8", "6", "6", "103", "129", "8", "1", "1", "1", "48", "28", "6", "9", "42", "134", "72", "134", "247", "13", "1", "9", "5", "49", "15", "23", "13", "49", "57", "49", "50", "49", "54", "49", "55", "50", "50", "51", "56", "90", "48", "47", "6", "9", "42", "134", "72", "134", "247", "13", "1", "9", "4", "49", "34", "4", "32", "32", "85", "108", "174", "127", "112", "178", "182", "8", "43", "134", "123", "192", "211", "131", "66", "184", "240", "212", "181", "240", "180", "106", "195", "24", "117", "54", "129", "19", "10", "250", "53"].iter().map(|&s| s.to_string()).collect();
        let pubkey_vec: Vec<String> = vec![ "14877258137020857405", "14318023465818440622", "669762396243626034", "2098174905787760109", "13512184631463232752", "1151033230807403051", "1750794423069476136", "5398558687849555435", "7358703642447293896", "14972964178681968444", "17927376393065624666", "12136698642738483635", "13028589389954236416", "11728294669438967583", "11944475542136244450", "12725379692537957031", "16433947280623454013", "13881303350788339044", "8072426876492282526", "6117387215636660433", "4538720981552095319", "1804042726655603403", "5977651198873791747", "372166053406449710", "14344596050894147197", "10779070237704917237", "16780599956687811964", "17935955203645787728", "16348714160740996118", "15226818430852970175", "10311930392912784455", "16078982568357050303"].iter().map(|&s| s.to_string()).collect();
        let signature_vec: Vec<String> = vec![ "5246435566823387901", "994140068779018945", "15914471451186462512", "7880571667552251248", "6469307986104572621", "12461949630634658221", "12450885696843643385", "13947454655189776216", "15974551328200116785", "931381626091656069", "1385903161379602775", "12855786061091617297", "15094260651801937779", "13471621228825251570", "17294887199620944108", "14311703967543697647", "12973402331891058776", "4499641933342092059", "10578231994395748441", "10761169031539003508", "9946908810756942959", "4164708910663312563", "1838078345835967157", "3031966336456751199", "12952597393846567366", "7709884308070068222", "2297541532764959033", "6155424118644397184", "10223511940510133693", "2888993604729528860", "2817846539210919674", "9919760476291903645"].iter().map(|&s| s.to_string()).collect();
        let address_str: String = "0xEde0fA5A7b196F512204f286666E5eC03E1005D2".to_string();

        parse_and_insert(&mut inputs, "mrz", mrz_vec.iter().map(AsRef::as_ref).collect());
        parse_and_insert(&mut inputs, "reveal_bitmap", reveal_bitmap_vec.iter().map(AsRef::as_ref).collect());
        parse_and_insert(&mut inputs, "dataHashes", data_hashes_vec.iter().map(AsRef::as_ref).collect());
        parse_and_insert(&mut inputs, "eContentBytes", e_content_bytes_vec.iter().map(AsRef::as_ref).collect());
        parse_and_insert(&mut inputs, "signature", signature_vec.iter().map(AsRef::as_ref).collect());
        parse_and_insert(&mut inputs, "pubkey", pubkey_vec.iter().map(AsRef::as_ref).collect());
    
        let address_bigint = BigInt::from_bytes_be(Sign::Plus, &decode(&address_str[2..])?);
        inputs.insert("address".to_string(), vec![address_bigint]);

        let datahashes_padded_length_i32 = datahashes_padded_length_str.parse::<i32>().expect("Failed to parse datahashes_padded_length to i32");
        let datahashes_padded_length_bigint = BigInt::from(datahashes_padded_length_i32);
        inputs.insert("datahashes_padded_length".to_string(), vec![datahashes_padded_length_bigint]);

        println!("generating witness...");
        let now = Instant::now();
        let full_assignment = witness_calculator()
            .lock()
            .expect("Failed to lock witness calculator")
            .calculate_witness_element::<Bn254, _>(inputs, false)
            .map_err(|e| e.to_string())?;
        
        println!("Witness generation took: {:.2?}", now.elapsed());
        println!("loading circuit...");
        let now = Instant::now();
        let zkey = arkzkey();
        println!("Loading arkzkey took: {:.2?}", now.elapsed());

        let public_inputs = full_assignment.as_slice()[1..zkey.1.num_instance_variables].to_vec();
        let now = Instant::now();
        let ark_proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
            &zkey.0,
            r,
            s,
            &zkey.1,
            zkey.1.num_instance_variables,
            zkey.1.num_constraints,
            full_assignment.as_slice(),
        );
    
        let proof = ark_proof.map_err(|e| e.to_string())?;
    
        println!("proof generation took: {:.2?}", now.elapsed());
    
        println!("proof {:?}", proof);
        println!("public_inputs {:?}", public_inputs);

        Ok(())
        // Ok((SerializableProof(proof), SerializableInputs(public_inputs)))
        // now = Instant::now();
        
        // let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
        // let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
        // println!("Proof verified. Took: {:?}", now.elapsed());
    
        // assert!(verified);
    
        // // launch the network & compile the verifier
        // println!("launching network");
        
        // let anvil = Anvil::new().spawn();
        // let acc = anvil.addresses()[0];
        // let provider = Provider::<Http>::try_from(anvil.endpoint())?;
        // let provider = provider.with_sender(acc);
        // let provider = Arc::new(provider);
        
        // // deploy the verifier
        // let contract = Groth16Verifier::deploy(provider.clone(), ())?
        // .send()
        // .await?;
    
        // println!("verifier deployed");
        // println!("contract {:?}", contract);
        // // check the proof on chain
        // let onchain_verified = contract
        // .check_proof(proof, params.vk, inputs.as_slice())
        // .await?;
    
        // println!("proof verified on chain");
        // println!("onchain_verified {:?}", onchain_verified);
    
        // assert!(onchain_verified);
    
        // Ok(())
    }
}
