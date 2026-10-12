//! Baut beim Kompilieren des Daemons automatisch den eBPF-Sensor.
//!
//! Setzt die Umgebungsvariable `EXEC_EBPF_OBJECT` auf den Pfad des fertigen
//! eBPF-Objekts. Das Objekt wird beim Compilieren per `include_bytes_aligned!`
//! in die Daemon-Binärdatei eingebettet (kein Dateipfad zur Laufzeit, kein
//! `AYA_BUILD_OBJ`, kein `--obj`-Argument mehr). Fehlt das Objekt (z. B. weil
//! `AYA_BUILD_SKIP=1` den Build übersprungen hat), schlägt der Compile
//! fail-closed fehl statt zur Laufzeit einen Pfad zu suchen.

use std::{env, path::PathBuf};

use aya_build::{build_ebpf, Package, Result, Toolchain};

fn main() -> Result<()> {
    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR not set");

    // Explizite Build-Eingaben: Eine Änderung am Sensor, seinem Manifest oder
    // dem ABI muss das eingebettete Objekt neu erzeugen.
    println!("cargo:rerun-if-changed=../exec-observer-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../exec-observer-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=../exec-observer-uapi/src/lib.rs");
    println!("cargo:rerun-if-changed=../exec-observer-uapi/Cargo.toml");

    build_ebpf(
        [Package {
            name: "exec-observer-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../exec-observer-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Nightly,
    )?;

    let obj = PathBuf::from(out_dir).join("exec-observer-ebpf");
    println!("cargo:rustc-env=EXEC_EBPF_OBJECT={}", obj.display());
    Ok(())
}
