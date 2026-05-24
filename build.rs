#![allow(clippy::panic)]

fn main() {
    // Only compile the BPF stub when the kernel-bpf feature is enabled.
    #[cfg(feature = "kernel-bpf")]
    {
        use std::env;
        use std::path::Path;
        use std::process::Command;

        let out_dir = env::var_os("OUT_DIR").unwrap_or_default();
        let dest_path = Path::new(&out_dir).join("sieve.bpf.o");

        let src = "src/bpf/sieve.bpf.c";
        println!("cargo:rerun-if-changed={src}");

        if Path::new(src).exists() {
            let status = Command::new("clang")
                .args(["-target", "bpf", "-g", "-O2", "-c", src, "-o"])
                .arg(&dest_path)
                .status();

            match status {
                Ok(s) if s.success() => {
                    // Compilation succeeded
                }
                Ok(s) => {
                    panic!(
                        "Failed to compile BPF object with clang (exit code: {:?}). \
                         Install clang and ensure it supports -target bpf.",
                        s.code()
                    );
                }
                Err(e) => {
                    panic!(
                        "Failed to run clang to compile BPF object: {e}. \
                         Install clang to build the kernel-bpf feature."
                    );
                }
            }
        } else {
            panic!("BPF source file {src} not found. Cannot build kernel-bpf feature.");
        }
    }
}
