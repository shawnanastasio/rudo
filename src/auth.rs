/**
 * auth.rs - Authentication functions. Interfaces with PAM wrapper
 */

use std::io;
use std::io::Write;
use std::ffi::CString;

use settings::Settings;

// rpassword crate to read passwords from user
extern crate rpassword;
use self::rpassword::read_password;

extern crate users;
use self::users::get_user_by_uid;
use self::users::get_current_uid;

// C function prototypes
extern "C" {
    // Functions from pamwrapper
    // bool check_authentication(const char *user, const char *pass);
    pub fn check_authentication(username: *const i8, password: *const i8) -> bool;
}

pub fn get_username() -> String {
    let user = get_user_by_uid(get_current_uid()).unwrap();
    let username = &user.name();
    String::from(*username)
}

/**
 * authenticate_current_user - Ask the user for a password and call pam binding to check it
 * @return bool did user authenticate successfully?
 */
pub fn authenticate_current_user(settings: &Settings) -> bool {
    // Get the current user's username and convert it to a C string
    let username = get_username();
    let c_username = CString::new(username).unwrap();

    // Prompt the user for a password using the prompt from the settings
    print!("{}", settings.get_prompt());
    io::stdout().flush().expect("Failed to flush stdout!");
    let password = read_password().unwrap();

    // Convert the password into a C String
    let c_password = CString::new(password).unwrap();

    // Authenticate with the username and password on the C pam bindings
    let res: bool;
    unsafe {
        res = check_authentication(c_username.as_ptr(), c_password.as_ptr());
    }

    res
}

// Try to authenticate a user n times
pub fn authenticate_current_user_n(settings: &Settings, n: i32) -> bool {
    for i in 0..n {
        if authenticate_current_user(settings) {
            break;
        } else if i == n-1 {
            writeln!(&mut io::stderr(), "Too many failed password attempts!")
            .expect("Failed to write to stderr!");
            return false
        } else {
            writeln!(&mut io::stderr(), "Invalid password! Try again.")
            .expect("Failed to write to stderr!");
        }
    }
    true
}
