use color_eyre::eyre::Result;
use std::env;
use std::path::PathBuf;

fn prepare_env(zkey_path: String, wasm_path: String, arkzkey_path: String) -> Result<()> {
    let project_dir = env::var("CARGO_MANIFEST_DIR")?;
    let zkey_file = PathBuf::from(&project_dir).join(zkey_path);
    let wasm_file = PathBuf::from(&project_dir).join(wasm_path);
    let arkzkey_file = PathBuf::from(&project_dir).join(arkzkey_path);

    // TODO: Right now emitting as warnings for visibility, figure out better way to do this?
    println!("cargo:warning=zkey_file: {}", zkey_file.display());
    println!("cargo:warning=wasm_file: {}", wasm_file.display());
    println!("cargo:warning=arkzkey_file: {}", arkzkey_file.display());

    // Set BUILD_RS_ZKEY_FILE and BUILD_RS_WASM_FILE env var
    println!("cargo:rustc-env=BUILD_RS_ZKEY_FILE={}", zkey_file.display());
    println!("cargo:rustc-env=BUILD_RS_WASM_FILE={}", wasm_file.display());
    println!(
        "cargo:rustc-env=BUILD_RS_ARKZKEY_FILE={}",
        arkzkey_file.display()
    );

    Ok(())
}

#[cfg(feature = "dylib")]
fn build_dylib(wasm_path: String, dylib_name: String) -> Result<()> {
    use std::path::Path;
    use std::{fs, str::FromStr};

    use color_eyre::eyre::eyre;
    use enumset::enum_set;
    use enumset::EnumSet;

    use wasmer::Cranelift;
    use wasmer::Dylib;
    use wasmer::Target;
    use wasmer::{Module, Store, Triple};

    let out_dir = env::var("OUT_DIR")?;
    let project_dir = env::var("CARGO_MANIFEST_DIR")?;
    let build_mode = env::var("PROFILE")?;
    let target_arch = env::var("TARGET")?;

    let out_dir = Path::new(&out_dir).to_path_buf();
    let wasm_file = Path::new(&wasm_path).to_path_buf();
    let dylib_file = out_dir.join(&dylib_name);
    let final_dir = PathBuf::from(&project_dir)
        .join("target")
        .join(&target_arch)
        .join(build_mode);

    // if dylib_file.exists() {
    //     return Ok(());
    // }

    // Create a WASM engine for the target that can compile
    let triple = Triple::from_str(&target_arch).map_err(|e| eyre!(e))?;
    let cpu_features = enum_set!();
    let target = Target::new(triple, cpu_features);
    let engine = Dylib::new(Cranelift::default()).target(target).engine();
    println!("cargo:warning=Building dylib for {}", target_arch);

    // Compile the WASM module
    let store = Store::new(&engine);
    let module = Module::from_file(&store, &wasm_file).unwrap();
    module.serialize_to_file(&dylib_file).unwrap();
    assert!(dylib_file.exists());

    // Copy dylib to a more predictable path
    fs::create_dir_all(&final_dir)?;
    let final_path = final_dir.join(dylib_name);
    fs::copy(&dylib_file, &final_path)?;
    println!("cargo:warning=Dylib location: {}", final_path.display());

    Ok(())
}

fn main() -> Result<()> {
    // TODO: build_circuit function to builds all related artifacts, instead of doing this externally
    let dir = "../../circuits";
    let circuit = "proof_of_passport";

    let zkey_path = format!("{}/build/{}_final.zkey", dir, circuit);
    let wasm_path = format!("{}/build/{}_js/{}.wasm", dir, circuit, circuit);
    // TODO: Need to modify script for this
    let arkzkey_path = format!("{}/build/{}_final.arkzkey", dir, circuit);

    println!("cargo:warning=arkzkey_path: {}", arkzkey_path);

    #[cfg(feature = "dylib")]
    {
        let _ = build_dylib(wasm_path.clone(), "proof_of_passport.dylib".to_string());
    }

    prepare_env(zkey_path, wasm_path, arkzkey_path)?;

    Ok(())
}
