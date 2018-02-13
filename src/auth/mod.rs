//mod touchid;
use std::error::Error;
use std::io::prelude::*;
use std::io;
use std::cmp;

extern crate rpassword;
extern crate users;

use ::session::create_session;
use ::session::check_session;

use ::settings::Settings;

#[cfg(feature = "pam")]
pub mod pam;
#[cfg(feature = "pam")]
use self::pam::*;

/// Interface for authentication frameworks
pub trait AuthFramework {
    fn authenticate(&self) -> Result<bool, Box<Error>>;
    fn get_max_tries(&self) -> i32;
}

pub fn authenticate_current_user_n(settings: &Settings, n: i32)
    -> Result<bool, Box<Error>> {

    // If the user already has a valid session, skip authentication
    let username = get_username()?;
    let has_session = check_session(&username)?;
    if has_session { return Ok(true); }

    // Instantiate all supported frameworks
    let mut frameworks: Vec<Box<AuthFramework>> = Vec::new();

    #[cfg(feature = "pam")]
    {
        frameworks.push(Box::new(PamAuthFramework::new(settings)));
    }

    let mut authenticated: bool = false;
    for f in frameworks.iter() {
        // Determine maximum number of attempts for this framework
        let mut max_tries = f.get_max_tries();
        if max_tries == 0 {
            max_tries = n;
        } else {
            max_tries = cmp::max(max_tries, n);
        }

        // Try to authenticate using this framework
        for i in 0..max_tries {
            let res = f.authenticate()?;
            if res {
                authenticated = true;
                break;
            }

            if i != max_tries - 1 {
                writeln!(&mut io::stderr(), "Invalid credentials. Try again.").unwrap();
            }
        }

        // If authentication succeeded, break
        if authenticated { break; }
    }

    // If authentication was successful, crate a new session
    if authenticated && settings.session_timeout_sec > 0 {
        create_session(&username, settings.session_timeout_sec)?;
    }

    Ok(authenticated)
}