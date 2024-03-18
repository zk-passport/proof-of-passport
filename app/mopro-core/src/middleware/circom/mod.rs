use self::{
    serialization::{SerializableInputs, SerializableProof, SerializableProvingKey},
    utils::{assert_paths_exists, bytes_to_bits},
};
use crate::MoproError;

use std::collections::HashMap;
//use std::io::Cursor;
use std::sync::Mutex;
use std::time::Instant;

use ark_bn254::{Bn254, Fr};
use ark_circom::{
    CircomBuilder,
    CircomCircuit,
    CircomConfig,
    CircomReduction,
    WitnessCalculator, //read_zkey,
};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey};
use ark_std::UniformRand;

use ark_relations::r1cs::ConstraintMatrices;
use ark_std::rand::thread_rng;
use color_eyre::Result;
use core::include_bytes;
use num_bigint::BigInt;
use once_cell::sync::{Lazy, OnceCell};

use wasmer::{Module, Store};

use ark_zkey::read_arkzkey_from_bytes; //SerializableConstraintMatrices

#[cfg(feature = "dylib")]
use {
    std::{env, path::Path},
    wasmer::Dylib,
};

pub mod serialization;
pub mod utils;

type GrothBn = Groth16<Bn254>;

type CircuitInputs = HashMap<String, Vec<BigInt>>;

// TODO: Split up this namespace a bit, right now quite a lot of things going on

pub struct CircomState {
    builder: Option<CircomBuilder<Bn254>>,
    circuit: Option<CircomCircuit<Bn254>>,
    params: Option<ProvingKey<Bn254>>,
}

impl Default for CircomState {
    fn default() -> Self {
        Self::new()
    }
}

// NOTE: A lot of the contents of this file is inspired by github.com/worldcoin/semaphore-rs

// TODO: Replace printlns with logging

//const ZKEY_BYTES: &[u8] = include_bytes!(env!("BUILD_RS_ZKEY_FILE"));

const ARKZKEY_BYTES: &[u8] = include_bytes!(env!("BUILD_RS_ARKZKEY_FILE"));

// static ZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
//     let mut reader = Cursor::new(ZKEY_BYTES);
//     read_zkey(&mut reader).expect("Failed to read zkey")
// });

static ARKZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    //let mut reader = Cursor::new(ARKZKEY_BYTES);
    // TODO: Use reader? More flexible; unclear if perf diff
    read_arkzkey_from_bytes(ARKZKEY_BYTES).expect("Failed to read arkzkey")
});

// const WASM: &[u8] = include_bytes!(env!("BUILD_RS_WASM_FILE"));

// `WITNESS_CALCULATOR` is a lazily initialized, thread-safe singleton of type `WitnessCalculator`.
// `OnceCell` ensures that the initialization occurs exactly once, and `Mutex` allows safe shared
// access from multiple threads.
static WITNESS_CALCULATOR: OnceCell<Mutex<WitnessCalculator>> = OnceCell::new();

// Initializes the `WITNESS_CALCULATOR` singleton with a `WitnessCalculator` instance created from
// a specified dylib file (WASM circuit). Also initialize `ZKEY`.
#[cfg(feature = "dylib")]
pub fn initialize(dylib_path: &Path) {
    println!("Initializing dylib: {:?}", dylib_path);

    WITNESS_CALCULATOR
        .set(from_dylib(dylib_path))
        .expect("Failed to set WITNESS_CALCULATOR");

    println!("witness calculator initialized");

    // Initialize ARKZKEY
    // TODO: Speed this up even more
    let now = std::time::Instant::now();
    Lazy::force(&ARKZKEY);
    println!("Initializing arkzkey took: {:.2?}", now.elapsed());
}

#[cfg(not(feature = "dylib"))]
pub fn initialize() {
    println!("Initializing library with arkzkey");

    // Initialize ARKZKEY
    // TODO: Speed this up even more!
    let now = std::time::Instant::now();
    Lazy::force(&ARKZKEY);
    println!("Initializing arkzkey took: {:.2?}", now.elapsed());
}

// Creates a `WitnessCalculator` instance from a dylib file.
#[cfg(feature = "dylib")]
fn from_dylib(path: &Path) -> Mutex<WitnessCalculator> {
    let store = Store::new(&Dylib::headless().engine());
    let module = unsafe {
        Module::deserialize_from_file(&store, path).expect("Failed to load dylib module")
    };
    let result =
        WitnessCalculator::from_module(module).expect("Failed to create WitnessCalculator");

    Mutex::new(result)
}

// #[must_use]
// pub fn zkey() -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
//     &ZKEY
// }

// Experimental
#[must_use]
pub fn arkzkey() -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
    &ARKZKEY
}

// Provides access to the `WITNESS_CALCULATOR` singleton, initializing it if necessary.
// It expects the path to the dylib file to be set in the `CIRCUIT_WASM_DYLIB` environment variable.
#[cfg(feature = "dylib")]
#[must_use]
pub fn witness_calculator() -> &'static Mutex<WitnessCalculator> {
    let var_name = "CIRCUIT_WASM_DYLIB";

    WITNESS_CALCULATOR.get_or_init(|| {
        let path = env::var(var_name).unwrap_or_else(|_| {
            panic!(
                "Mopro circuit WASM Dylib not initialized. \
            Please set {} environment variable to the path of the dylib file",
                var_name
            )
        });
        from_dylib(Path::new(&path))
    })
}

// #[cfg(not(feature = "dylib"))]
// #[must_use]
// pub fn witness_calculator() -> &'static Mutex<WitnessCalculator> {
//     WITNESS_CALCULATOR.get_or_init(|| {
//         let store = Store::default();
//         let module = Module::from_binary(&store, WASM).expect("WASM should be valid");
//         let result =
//             WitnessCalculator::from_module(module).expect("Failed to create WitnessCalculator");
//         Mutex::new(result)
//     })
// }

pub fn generate_proof2(
    inputs: CircuitInputs,
) -> Result<(SerializableProof, SerializableInputs), MoproError> {
    let mut rng = thread_rng();
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    println!("Generating proof 2");

    let now = std::time::Instant::now();
    let full_assignment = witness_calculator()
        .lock()
        .expect("Failed to lock witness calculator")
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(|e| MoproError::CircomError(e.to_string()))?;

    println!("Witness generation took: {:.2?}", now.elapsed());

    let now = std::time::Instant::now();
    //let zkey = zkey();
    let zkey = arkzkey();
    println!("Loading arkzkey took: {:.2?}", now.elapsed());

    let public_inputs = full_assignment.as_slice()[1..zkey.1.num_instance_variables].to_vec();

    let now = std::time::Instant::now();
    let ark_proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
        full_assignment.as_slice(),
    );

    let proof = ark_proof.map_err(|e| MoproError::CircomError(e.to_string()))?;

    println!("proof generation took: {:.2?}", now.elapsed());

    // TODO: Add SerializableInputs(inputs)))
    Ok((SerializableProof(proof), SerializableInputs(public_inputs)))
}

pub fn verify_proof2(
    serialized_proof: SerializableProof,
    serialized_inputs: SerializableInputs,
) -> Result<bool, MoproError> {
    let start = Instant::now();
    let zkey = arkzkey();
    let pvk = prepare_verifying_key(&zkey.0.vk);

    let proof_verified =
        GrothBn::verify_with_processed_vk(&pvk, &serialized_inputs.0, &serialized_proof.0)
            .map_err(|e| MoproError::CircomError(e.to_string()))?;

    let verification_duration = start.elapsed();
    println!("Verification time 2: {:?}", verification_duration);
    Ok(proof_verified)
}

impl CircomState {
    pub fn new() -> Self {
        Self {
            builder: None,
            circuit: None,
            params: None,
        }
    }

    pub fn setup(
        &mut self,
        wasm_path: &str,
        r1cs_path: &str,
    ) -> Result<SerializableProvingKey, MoproError> {
        assert_paths_exists(wasm_path, r1cs_path)?;
        println!("Setup");
        let start = Instant::now();

        // Load the WASM and R1CS for witness and proof generation
        let cfg = self.load_config(wasm_path, r1cs_path)?;

        // Create an empty instance for setup
        self.builder = Some(CircomBuilder::new(cfg));

        // Run a trusted setup using the rng in the state
        let params = self.run_trusted_setup()?;

        self.params = Some(params.clone());

        let setup_duration = start.elapsed();
        println!("Setup time: {:?}", setup_duration);

        Ok(SerializableProvingKey(params))
    }

    // NOTE: Consider generate_proof<T: Into<BigInt>> API
    // XXX: BigInt might present problems for UniFFI
    pub fn generate_proof(
        &mut self,
        inputs: CircuitInputs,
    ) -> Result<(SerializableProof, SerializableInputs), MoproError> {
        let start = Instant::now();
        println!("Generating proof");

        let mut rng = thread_rng();

        let builder = self.builder.as_mut().ok_or(MoproError::CircomError(
            "Builder has not been set up".to_string(),
        ))?;

        // Insert our inputs as key value pairs
        for (key, values) in &inputs {
            for value in values {
                builder.push_input(&key, value.clone());
            }
        }

        // Clone the builder, then build the circuit
        let circom = builder
            .clone()
            .build()
            .map_err(|e| MoproError::CircomError(e.to_string()))?;

        // Update the circuit in self
        self.circuit = Some(circom.clone());

        let params = self.params.as_ref().ok_or(MoproError::CircomError(
            "Parameters have not been set up".to_string(),
        ))?;

        let inputs = circom.get_public_inputs().ok_or(MoproError::CircomError(
            "Failed to get public inputs".to_string(),
        ))?;

        let proof = GrothBn::prove(params, circom.clone(), &mut rng)
            .map_err(|e| MoproError::CircomError(e.to_string()))?;

        let proof_duration = start.elapsed();
        println!("Proof generation time: {:?}", proof_duration);

        Ok((SerializableProof(proof), SerializableInputs(inputs)))
    }

    pub fn verify_proof(
        &self,
        serialized_proof: SerializableProof,
        serialized_inputs: SerializableInputs,
    ) -> Result<bool, MoproError> {
        let start = Instant::now();

        println!("Verifying proof");

        let params = self.params.as_ref().ok_or(MoproError::CircomError(
            "Parameters have not been set up".to_string(),
        ))?;

        let pvk =
            GrothBn::process_vk(&params.vk).map_err(|e| MoproError::CircomError(e.to_string()))?;

        let proof_verified =
            GrothBn::verify_with_processed_vk(&pvk, &serialized_inputs.0, &serialized_proof.0)
                .map_err(|e| MoproError::CircomError(e.to_string()))?;

        let verification_duration = start.elapsed();
        println!("Verification time: {:?}", verification_duration);
        Ok(proof_verified)
    }

    fn load_config(
        &self,
        wasm_path: &str,
        r1cs_path: &str,
    ) -> Result<CircomConfig<Bn254>, MoproError> {
        CircomConfig::<Bn254>::new(wasm_path, r1cs_path)
            .map_err(|e| MoproError::CircomError(e.to_string()))
    }

    fn run_trusted_setup(&mut self) -> Result<ProvingKey<Bn254>, MoproError> {
        let circom_setup = self
            .builder
            .as_mut()
            .ok_or(MoproError::CircomError(
                "Builder has not been set up".to_string(),
            ))?
            .setup();

        let mut rng = thread_rng();

        GrothBn::generate_random_parameters_with_reduction(circom_setup, &mut rng)
            .map_err(|e| MoproError::CircomError(e.to_string()))
    }
}

// Helper function for Keccak256 example
pub fn bytes_to_circuit_inputs(bytes: &[u8]) -> CircuitInputs {
    let bits = bytes_to_bits(bytes);
    let big_int_bits = bits
        .into_iter()
        .map(|bit| BigInt::from(bit as u8))
        .collect();
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), big_int_bits);
    inputs
}

pub fn strings_to_circuit_inputs(strings: &[&str]) -> Vec<BigInt> {
    strings
        .iter()
        .map(|&value| BigInt::parse_bytes(value.as_bytes(), 10).unwrap())
        .collect()
}

pub fn bytes_to_circuit_outputs(bytes: &[u8]) -> SerializableInputs {
    let bits = bytes_to_bits(bytes);
    let field_bits = bits.into_iter().map(|bit| Fr::from(bit as u8)).collect();
    SerializableInputs(field_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_prove_verify_simple() {
        let wasm_path = "./examples/circom/multiplier2/target/multiplier2_js/multiplier2.wasm";
        let r1cs_path = "./examples/circom/multiplier2/target/multiplier2.r1cs";

        // Instantiate CircomState
        let mut circom_state = CircomState::new();

        // Setup
        let setup_res = circom_state.setup(wasm_path, r1cs_path);
        assert!(setup_res.is_ok());

        let _serialized_pk = setup_res.unwrap();

        // Deserialize the proving key and inputs if necessary

        // Prepare inputs
        let mut inputs = HashMap::new();
        let a = 3;
        let b = 5;
        let c = a * b;
        inputs.insert("a".to_string(), vec![BigInt::from(a)]);
        inputs.insert("b".to_string(), vec![BigInt::from(b)]);
        // output = [public output c, public input a]
        let expected_output = vec![Fr::from(c), Fr::from(a)];
        let serialized_outputs = SerializableInputs(expected_output);

        // Proof generation
        let generate_proof_res = circom_state.generate_proof(inputs);

        // Check and print the error if there is one
        if let Err(e) = &generate_proof_res {
            println!("Error: {:?}", e);
        }

        assert!(generate_proof_res.is_ok());

        let (serialized_proof, serialized_inputs) = generate_proof_res.unwrap();

        // Check output
        assert_eq!(serialized_inputs, serialized_outputs);

        // Proof verification
        let verify_res = circom_state.verify_proof(serialized_proof, serialized_inputs);
        assert!(verify_res.is_ok());
        assert!(verify_res.unwrap()); // Verifying that the proof was indeed verified
    }

    #[test]
    fn test_setup_prove_verify_keccak() {
        let wasm_path =
            "./examples/circom/keccak256/target/keccak256_256_test_js/keccak256_256_test.wasm";
        let r1cs_path = "./examples/circom/keccak256/target/keccak256_256_test.r1cs";

        // Instantiate CircomState
        let mut circom_state = CircomState::new();

        // Setup
        let setup_res = circom_state.setup(wasm_path, r1cs_path);
        assert!(setup_res.is_ok());

        let _serialized_pk = setup_res.unwrap();

        // Deserialize the proving key and inputs if necessary

        // Prepare inputs
        let input_vec = vec![
            116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        // Expected output
        let expected_output_vec = vec![
            37, 17, 98, 135, 161, 178, 88, 97, 125, 150, 143, 65, 228, 211, 170, 133, 153, 9, 88,
            212, 4, 212, 175, 238, 249, 210, 214, 116, 170, 85, 45, 21,
        ];

        let inputs = bytes_to_circuit_inputs(&input_vec);
        let serialized_outputs = bytes_to_circuit_outputs(&expected_output_vec);

        // Proof generation
        let generate_proof_res = circom_state.generate_proof(inputs);

        // Check and print the error if there is one
        if let Err(e) = &generate_proof_res {
            println!("Error: {:?}", e);
        }

        assert!(generate_proof_res.is_ok());

        let (serialized_proof, serialized_inputs) = generate_proof_res.unwrap();

        // Check output
        assert_eq!(serialized_inputs, serialized_outputs);

        // Proof verification
        let verify_res = circom_state.verify_proof(serialized_proof, serialized_inputs);
        assert!(verify_res.is_ok());

        assert!(verify_res.unwrap()); // Verifying that the proof was indeed verified
    }

    #[test]
    fn test_setup_error() {
        // Arrange: Create a new CircomState instance
        let mut circom_state = CircomState::new();

        let wasm_path = "badpath/multiplier2.wasm";
        let r1cs_path = "badpath/multiplier2.r1cs";

        // Act: Call the setup method
        let result = circom_state.setup(wasm_path, r1cs_path);

        // Assert: Check that the method returns an error
        assert!(result.is_err());
    }

    #[cfg(feature = "dylib")]
    #[test]
    fn test_dylib_init_and_generate_witness() {
        // Assumes that the dylib file has been built and is in the following location
        let dylib_path = "target/debug/aarch64-apple-darwin/keccak256.dylib";

        // Initialize libray
        initialize(Path::new(&dylib_path));

        let input_vec = vec![
            116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        let inputs = bytes_to_circuit_inputs(&input_vec);
        let now = std::time::Instant::now();
        let full_assignment = witness_calculator()
            .lock()
            .expect("Failed to lock witness calculator")
            .calculate_witness_element::<Bn254, _>(inputs, false)
            .map_err(|e| MoproError::CircomError(e.to_string()));

        println!("Witness generation took: {:.2?}", now.elapsed());

        assert!(full_assignment.is_ok());
    }

    #[test]
    fn test_generate_proof2() {
        // XXX: This can be done better
        #[cfg(feature = "dylib")]
        {
            // Assumes that the dylib file has been built and is in the following location
            let dylib_path = "target/debug/aarch64-apple-darwin/keccak256.dylib";

            // Initialize libray
            initialize(Path::new(&dylib_path));
        }

        let input_vec = vec![
            116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let expected_output_vec = vec![
            37, 17, 98, 135, 161, 178, 88, 97, 125, 150, 143, 65, 228, 211, 170, 133, 153, 9, 88,
            212, 4, 212, 175, 238, 249, 210, 214, 116, 170, 85, 45, 21,
        ];
        let inputs = bytes_to_circuit_inputs(&input_vec);
        let serialized_outputs = bytes_to_circuit_outputs(&expected_output_vec);

        let generate_proof_res = generate_proof2(inputs);
        let (serialized_proof, serialized_inputs) = generate_proof_res.unwrap();
        assert_eq!(serialized_inputs, serialized_outputs);

        // Proof verification
        let verify_res = verify_proof2(serialized_proof, serialized_inputs);
        assert!(verify_res.is_ok());
        assert!(verify_res.unwrap()); // Verifying that the proof was indeed verified
    }

    #[ignore = "ignore for ci"]
    #[test]
    fn test_setup_prove_rsa() {
        let wasm_path = "./examples/circom/rsa/target/main_js/main.wasm";
        let r1cs_path = "./examples/circom/rsa/target/main.r1cs";

        // Instantiate CircomState
        let mut circom_state = CircomState::new();

        // Setup
        let setup_res = circom_state.setup(wasm_path, r1cs_path);
        assert!(setup_res.is_ok());

        let _serialized_pk = setup_res.unwrap();

        // Deserialize the proving key and inputs if necessary

        // Prepare inputs
        let signature = [
            "3582320600048169363",
            "7163546589759624213",
            "18262551396327275695",
            "4479772254206047016",
            "1970274621151677644",
            "6547632513799968987",
            "921117808165172908",
            "7155116889028933260",
            "16769940396381196125",
            "17141182191056257954",
            "4376997046052607007",
            "17471823348423771450",
            "16282311012391954891",
            "70286524413490741",
            "1588836847166444745",
            "15693430141227594668",
            "13832254169115286697",
            "15936550641925323613",
            "323842208142565220",
            "6558662646882345749",
            "15268061661646212265",
            "14962976685717212593",
            "15773505053543368901",
            "9586594741348111792",
            "1455720481014374292",
            "13945813312010515080",
            "6352059456732816887",
            "17556873002865047035",
            "2412591065060484384",
            "11512123092407778330",
            "8499281165724578877",
            "12768005853882726493",
        ];
        let modulus = [
            "13792647154200341559",
            "12773492180790982043",
            "13046321649363433702",
            "10174370803876824128",
            "7282572246071034406",
            "1524365412687682781",
            "4900829043004737418",
            "6195884386932410966",
            "13554217876979843574",
            "17902692039595931737",
            "12433028734895890975",
            "15971442058448435996",
            "4591894758077129763",
            "11258250015882429548",
            "16399550288873254981",
            "8246389845141771315",
            "14040203746442788850",
            "7283856864330834987",
            "12297563098718697441",
            "13560928146585163504",
            "7380926829734048483",
            "14591299561622291080",
            "8439722381984777599",
            "17375431987296514829",
            "16727607878674407272",
            "3233954801381564296",
            "17255435698225160983",
            "15093748890170255670",
            "15810389980847260072",
            "11120056430439037392",
            "5866130971823719482",
            "13327552690270163501",
        ];
        let base_message = [
            "18114495772705111902",
            "2254271930739856077",
            "2068851770",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
        ];

        let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();
        inputs.insert(
            "signature".to_string(),
            strings_to_circuit_inputs(&signature),
        );
        inputs.insert("modulus".to_string(), strings_to_circuit_inputs(&modulus));
        inputs.insert(
            "base_message".to_string(),
            strings_to_circuit_inputs(&base_message),
        );

        // Proof generation
        let generate_proof_res = circom_state.generate_proof(inputs);

        // Check and print the error if there is one
        if let Err(e) = &generate_proof_res {
            println!("Error: {:?}", e);
        }

        assert!(generate_proof_res.is_ok());

        let (serialized_proof, serialized_inputs) = generate_proof_res.unwrap();

        // Proof verification
        let verify_res = circom_state.verify_proof(serialized_proof, serialized_inputs);
        assert!(verify_res.is_ok());

        assert!(verify_res.unwrap()); // Verifying that the proof was indeed verified
    }

    #[ignore = "ignore for ci"]
    #[test]
    fn test_setup_prove_rsa2() {
        // Prepare inputs
        let signature = [
            "3582320600048169363",
            "7163546589759624213",
            "18262551396327275695",
            "4479772254206047016",
            "1970274621151677644",
            "6547632513799968987",
            "921117808165172908",
            "7155116889028933260",
            "16769940396381196125",
            "17141182191056257954",
            "4376997046052607007",
            "17471823348423771450",
            "16282311012391954891",
            "70286524413490741",
            "1588836847166444745",
            "15693430141227594668",
            "13832254169115286697",
            "15936550641925323613",
            "323842208142565220",
            "6558662646882345749",
            "15268061661646212265",
            "14962976685717212593",
            "15773505053543368901",
            "9586594741348111792",
            "1455720481014374292",
            "13945813312010515080",
            "6352059456732816887",
            "17556873002865047035",
            "2412591065060484384",
            "11512123092407778330",
            "8499281165724578877",
            "12768005853882726493",
        ];
        let modulus = [
            "13792647154200341559",
            "12773492180790982043",
            "13046321649363433702",
            "10174370803876824128",
            "7282572246071034406",
            "1524365412687682781",
            "4900829043004737418",
            "6195884386932410966",
            "13554217876979843574",
            "17902692039595931737",
            "12433028734895890975",
            "15971442058448435996",
            "4591894758077129763",
            "11258250015882429548",
            "16399550288873254981",
            "8246389845141771315",
            "14040203746442788850",
            "7283856864330834987",
            "12297563098718697441",
            "13560928146585163504",
            "7380926829734048483",
            "14591299561622291080",
            "8439722381984777599",
            "17375431987296514829",
            "16727607878674407272",
            "3233954801381564296",
            "17255435698225160983",
            "15093748890170255670",
            "15810389980847260072",
            "11120056430439037392",
            "5866130971823719482",
            "13327552690270163501",
        ];
        let base_message = [
            "18114495772705111902",
            "2254271930739856077",
            "2068851770",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0",
        ];

        let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();
        inputs.insert(
            "signature".to_string(),
            strings_to_circuit_inputs(&signature),
        );
        inputs.insert("modulus".to_string(), strings_to_circuit_inputs(&modulus));
        inputs.insert(
            "base_message".to_string(),
            strings_to_circuit_inputs(&base_message),
        );

        // Proof generation
        let generate_proof_res = generate_proof2(inputs);

        // Check and print the error if there is one
        if let Err(e) = &generate_proof_res {
            println!("Error: {:?}", e);
        }

        assert!(generate_proof_res.is_ok());

        let (serialized_proof, serialized_inputs) = generate_proof_res.unwrap();

        // Proof verification
        let verify_res = verify_proof2(serialized_proof, serialized_inputs);
        assert!(verify_res.is_ok());

        assert!(verify_res.unwrap()); // Verifying that the proof was indeed verified
    }
}
