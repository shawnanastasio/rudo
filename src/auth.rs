/**
 * auth.rs - Authentication functions. Interfaces with PAM wrapper
 */

use std::io;
use std::process;
use std::io::Write;
use std::ffi::CString;

use settings::Settings;

use session::check_session;
use session::create_session;

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

/// If touchid support is enabled, expose the needed CLocalAuthentication functions too
#[cfg(feature = "touchid")]
extern "C" {
    pub fn supports_touchid() -> bool;
    pub fn authenticate_user_touchid(reason: *const i8) -> bool;

    // Rust's libc crate doesn't yet have a binding for seteuid()
    // I have submitted a PR, but in the mean time this will do.
    pub fn seteuid(uid: u32) -> i32;
}

/// Wrapper for touchid authentication 
/// Returns true if user was able to authenticate with touchid
#[cfg(feature = "touchid")]
pub fn try_touchid_authenticate() -> bool {
    let res: bool;
    
    // Before authenticating with touchid, we must set our current UID to the caller
    unsafe { seteuid(get_current_uid()) };

    // See if current machine can use touchid and return early if we can't
    let can_touchid = unsafe { supports_touchid() };
    if !can_touchid {
        res = false;
    } else {
        // Try authenticating with touchid
        writeln!(&mut io::stderr(), "Authenticating with TouchID...").unwrap();
        res = unsafe { authenticate_user_touchid(CString::new("authenticate").unwrap().as_ptr()) }
    }

    // Reset our UID to root
    unsafe { seteuid(0) };

    res
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

    // Check to see if the current user/tty already has an ongoing session
    let username = get_username();
    let has_session = check_session(&username).unwrap();
    if has_session { return true; }

    // If we were compiled with touchid support, try authenticating with touchid
    #[cfg(feature = "touchid")]
    {
        let touchid_res = try_touchid_authenticate();
        if touchid_res {
            // If TouchID succeeded, create a new session and return true
            if settings.session_timeout_sec > 0 {
                create_session(&username, settings.session_timeout_sec).unwrap_or_else(|e| {
                    writeln!(&mut io::stderr(), "Failed to create session!: {}", e).unwrap();
                    process::exit(1);
                });
            }
            return true;
        }
        // If touchid failed, just fallback to standard PAM authentication.     
    }
    
    for i in 0..n {
        if authenticate_current_user(settings) {
            break;
        } else if i == n-1 {
            writeln!(&mut io::stderr(), "Too many failed password attempts!")
                .unwrap();
            return false
        } else {
            writeln!(&mut io::stderr(), "Invalid password! Try again.")
                .unwrap();
        }
    }

    // If we got here it means the user authenticated successfully, so let's
    // create a new session for them
    if settings.session_timeout_sec > 0 {
        create_session(&username, settings.session_timeout_sec).unwrap_or_else(|e| {
            writeln!(&mut io::stderr(), "Failed to create session!: {}", e).unwrap();
            process::exit(1);
        });
    }
    
    
    true
}
