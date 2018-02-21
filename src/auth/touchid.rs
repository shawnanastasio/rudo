use std::ffi::CString;
use std::error::Error;

use users::get_current_uid;

use settings::Settings;
use auth::AuthFramework;

// C function prototypes
extern "C" {
    pub fn supports_touchid() -> bool;
    pub fn authenticate_user_touchid(reason: *const i8) -> bool;

    // Rust's libc crate doesn't yet have a binding for seteuid()
    // I have submitted a PR, but in the mean time this will do.
    pub fn seteuid(uid: u32) -> i32;
}

const TOUCHID_MAX_TRIES: i32 = 1;
const TOUCHID_NAME: &'static str = "TouchID";

pub struct TouchIDAuthFramework<'a> {
    settings: &'a Settings
}

impl<'a> TouchIDAuthFramework<'a> {
    pub fn new(settings: &Settings) -> TouchIDAuthFramework {
        TouchIDAuthFramework {
            settings: settings
        }
    }
}

impl<'a> AuthFramework for TouchIDAuthFramework<'a> {
    fn authenticate(&self) -> Result<bool, Box<Error>> {
        // Set effective UID to the caller's UID so we can use TouchID
        unsafe { seteuid(get_current_uid()); }

        // See if this machine supports TouchID
        if ! unsafe { supports_touchid() } {
            return Err(From::from("Machine doesn't support TouchID!"));
        }

        let res: bool = unsafe { authenticate_user_touchid(CString::new("authenticate")?.as_ptr()) };
        
        // Reset our UID to root
        unsafe { seteuid(0); }

        Ok(res)
    }

    fn get_max_tries(&self) -> i32 {
        TOUCHID_MAX_TRIES
    }

    fn get_name(&self) -> &'static str {
        TOUCHID_NAME
    }
}
