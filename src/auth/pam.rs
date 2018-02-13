use std::ffi::CString;
use std::error::Error;
use std::io::prelude::*;
use std::io;

use auth::rpassword::read_password;

use auth::users::get_user_by_uid;
use auth::users::get_current_uid;

use ::settings::Settings;

use auth::AuthFramework;


// C function prototypes
extern "C" {
    // Functions from pamwrapper
    // bool check_authentication(const char *user, const char *pass);
    pub fn check_authentication(username: *const i8, password: *const i8) -> bool;
}

pub struct PamAuthFramework<'a> {
    settings: &'a Settings,
    max_tries: i32 // maximum number of authentication attempts, 0 for inf
}

impl<'a> PamAuthFramework<'a> {
    pub fn new(settings: &Settings) -> PamAuthFramework {
        PamAuthFramework {
            settings: settings,
            max_tries: 0
        }
    }
}

impl<'a> AuthFramework for PamAuthFramework<'a> {
    fn authenticate(&self) -> Result<bool, Box<Error>> {
        // Get the current user's username and convert it to a C string
        let username = get_username()?;
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
        return self.max_tries;
    }
}

pub fn get_username() -> Result<String, Box<Error>> {
    let user = get_user_by_uid(get_current_uid()).unwrap();
    let username = &user.name();
    Ok(String::from(*username))
}