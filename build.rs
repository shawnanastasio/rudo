extern crate gcc;

fn main() {
    // Build C PAM wrapper library
    gcc::compile_library("libpamwrapper.a", &["src/pamwrapper/pamwrapper.c"]);

    // Output rustc flags to link against libpam
    println!("cargo:rustc-flags=-l pam");
}
