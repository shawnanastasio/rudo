use std::error::Error;

extern crate users;
use self::users::get_user_by_name;
use self::users::get_group_by_name;
use self::users::get_user_by_uid;
use self::users::get_current_uid;

use osutils::OSUtils;

pub struct UnixOSUtils;

impl UnixOSUtils {
    pub fn new() -> UnixOSUtils {
        UnixOSUtils
    }
}

impl OSUtils for UnixOSUtils {
    fn get_username(&self) -> Result<String, Box<Error>> {
        match get_user_by_uid(get_current_uid()) {
            Some(u) => {
                Ok(String::from(u.name()))
            },

            None => {
                Err(From::from("Failed to obtain current username."))
            }
        }
    } 

    fn get_uidgid_by_username(&self, username: &str) -> Result<(u32, u32), Box<Error>> {
        match get_user_by_name(username) {
            Some(u) => {
                Ok((u.uid(), u.primary_group_id()))
            },

            None => {
                Err(From::from("Failed to obtain uid/gid for given username."))
            }
        }
    }

    fn get_gid_by_groupname(&self, groupname: &str) -> Result<u32, Box<Error>> {
        match get_group_by_name(groupname) {
            Some(g) => {
                Ok(g.gid())
            },

            None => {
                Err(From::from("Failed to obtain gid for given groupname."))
            }
        }
    }

    fn get_current_uid(&self) -> Result<u32, Box<Error>> {
        Ok(get_current_uid())
    }
} 
