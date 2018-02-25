use std::ffi::CString;
use std::error::Error;

use settings::Settings;
use auth::AuthFramework;
use osutils::OSUtils;

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

pub struct TouchIDAuthFramework<'a, T: OSUtils + 'a> {
    osutils: &'a T,
    settings: &'a Settings,
}

impl<'a, T> TouchIDAuthFramework<'a, T> where T: OSUtils {
    pub fn new(osutils: &'a T, settings: &'a Settings) -> TouchIDAuthFramework<'a, T> {
        TouchIDAuthFramework {
            osutils: osutils,
            settings: settings
        }
    }
}

impl<'a, T> AuthFramework for TouchIDAuthFramework<'a, T> where T: OSUtils {
    fn authenticate(&self) -> Result<bool, Box<Error>> {
        // Set effective UID to the caller's UID so we can use TouchID
        let current_uid = self.osutils.get_current_uid()?;
        unsafe { seteuid(current_uid); }

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
