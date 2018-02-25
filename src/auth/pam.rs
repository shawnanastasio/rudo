use std::ffi::CString;
use std::error::Error;
use std::io::prelude::*;
use std::io;

extern crate rpassword;
use self::rpassword::read_password;

use settings::Settings;
use auth::AuthFramework;
use osutils::OSUtils;

// C function prototypes
extern "C" {
    // Functions from pamwrapper
    // bool check_authentication(const char *user, const char *pass);
    pub fn check_authentication(username: *const i8, password: *const i8) -> bool;
}

const PAM_MAXTRIES: i32 = 0; 
const PAM_NAME: &'static str = "PAM";

pub struct PamAuthFramework<'a, T: OSUtils + 'a> {
    osutils: &'a T,
    settings: &'a Settings,
}

impl<'a, T> PamAuthFramework<'a, T> where T: OSUtils {
    pub fn new(osutils: &'a T, settings: &'a Settings) -> PamAuthFramework<'a, T> {
        PamAuthFramework {
            osutils: osutils,
            settings: settings,
        }
    }
}

impl<'a, T> AuthFramework for PamAuthFramework<'a, T> where T: OSUtils {
    fn authenticate(&self) -> Result<bool, Box<Error>> {
        // Get the current user's username and convert it to a C string
        let username = self.osutils.get_username()?;
        let c_username = CString::new(username)?;

        // Prompt the user for a password using the prompt from the settings
        print!("{}", self.settings.get_prompt());
        io::stdout().flush().expect("Failed to flush stdout!");
        let password = read_password()?;

        // Convert the password into a C String
        let c_password = CString::new(password)?;

        // Authenticate with the username and password on the C pam bindings
        let res: bool;
        unsafe {
            res = check_authentication(c_username.as_ptr(), c_password.as_ptr());
        }

        Ok(res)
    }

    fn get_max_tries(&self) -> i32 {
        PAM_MAXTRIES
    }

    fn get_name(&self) -> &'static str {
        PAM_NAME
    }
}
