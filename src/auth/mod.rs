use std::error::Error;
use std::io::prelude::*;
use std::io;
use std::cmp;

use session::create_session;
use session::check_session;

use settings::Settings;
use osutils::OSUtils;

#[cfg(feature = "pam")]
pub mod pam;
#[cfg(feature = "pam")]
use self::pam::*;

#[cfg(feature = "touchid")]
pub mod touchid;
#[cfg(feature = "touchid")]
use self::touchid::*;

/// Interface for authentication frameworks
pub trait AuthFramework {
    fn authenticate(&self) -> Result<bool, Box<dyn Error>>;
    fn get_max_tries(&self) -> i32;
    fn get_name(&self) -> &'static str;
}

pub fn authenticate_current_user_n<T: OSUtils>(osutils: &T, settings: &Settings, n: i32)
    -> Result<bool, Box<dyn Error>> {

    // If the user already has a valid session, skip authentication
    let username = osutils.get_username()?;
    let has_session = check_session(&username)?;
    if has_session { return Ok(true); }

    // Instantiate all supported frameworks
    let mut frameworks: Vec<Box<AuthFramework>> = Vec::new();
    
    #[cfg(feature = "touchid")]
    {
        frameworks.push(Box::new(TouchIDAuthFramework::<T>::new(osutils, settings)));
    }
    
    #[cfg(feature = "pam")]
    {
        frameworks.push(Box::new(PamAuthFramework::<T>::new(osutils, settings)));
    } 

    let mut authenticated: bool = false;
    for f in frameworks.iter() {
        // Determine maximum number of attempts for this framework
        let mut max_tries = f.get_max_tries();
        if max_tries == 0 {
            max_tries = n;
        } else {
            max_tries = cmp::min(max_tries, n);
        }

        // Try to authenticate using this framework
        for i in 0..max_tries {
            let res = f.authenticate()?;
            if res {
                authenticated = true;
                break;
            }

            if i != max_tries - 1 {
                writeln!(&mut io::stderr(), "Invalid credentials. Try again.")?;
            }
        }

        // If authentication succeeded, break
        if authenticated { 
            break; 
        } else {
            writeln!(&mut io::stderr(), "Failed to authenticate with {}.", f.get_name())?;
        }
    }

    // If authentication was successful, crate a new session
    if authenticated && settings.session_timeout_sec > 0 {
        create_session(&username, settings.session_timeout_sec)?;
    }

    Ok(authenticated)
}
