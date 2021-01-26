use std::error::Error;

pub mod unix;

pub trait OSUtils {
    /// Get the username of the current user
    fn get_username(&self) -> Result<String, Box<dyn Error>>;

    /// Get a uid and primary gid for the given username
    fn get_uidgid_by_username(&self, username: &str) -> Result<(u32, u32), Box<dyn Error>>;

    /// Get a gid for the given groupname
    fn get_gid_by_groupname(&self, groupname: &str) -> Result<u32, Box<dyn Error>>;

    /// Get the uid for the current user
    fn get_current_uid(&self) -> Result<u32, Box<dyn Error>>;
}
