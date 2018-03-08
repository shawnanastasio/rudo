extern crate cc;

use std::process::Command;

fn main() {
    // Build C PAM wrapper library if pam is enabled
    if cfg!(feature = "pam") { 
        cc::Build::new()
            .file("src/pamwrapper/pamwrapper.c")
            .compile("pamwrapper");
    }

    // Build CLocalAuthentication if on macOS and it was requested
    if cfg!(target_os = "macos") && cfg!(feature = "touchid") {
        // Clone CLocalAuthentication
        Command::new("mkdir").args(&["-p", "deps"]).status().unwrap();
        Command::new("git").args(&["clone", "https://github.com/shawnanastasio/CLocalAuthentication",
                                   "deps/CLocalAuthentication"]).status().unwrap();
        Command::new("sh").args(&["-c", "cd deps/CLocalAuthentication && git pull"])
            .status().unwrap();

        // Use xcodebuild to build it
        Command::new("sh").args(&["-c", "cd deps/CLocalAuthentication && xcodebuild build"])
            .status().unwrap();

        // Emit the correct linker flags to link against it
        println!("cargo:rustc-flags=-L deps/CLocalAuthentication/build/Release/");
        println!("cargo:rustc-flags=-l CLocalAuthentication");
    } else if cfg!(feature = "touchid") {
        panic!("TouchID support is only available on macOS!");
    }

    // Output rustc flags to link against libpam
    println!("cargo:rustc-flags=-l pam");
}
