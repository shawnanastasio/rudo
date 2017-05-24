use std::io::prelude::*;
use std::fs::File;
use std::error::Error;

use DEFAULT_PROMPT;

extern crate serde_json;

// List of permissions
#[derive(Serialize, Deserialize)]
pub struct Permissions {
    pub allowed_commands: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub permissions: Permissions

}

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub prompt: String,
    pub allowed_users: Vec<User>,
}

impl Settings {
    pub fn new() -> Settings {
        // Create an empty Settings struct with `root` as the only user
        let mut s = Settings {
            prompt: String::from(DEFAULT_PROMPT),
            allowed_users: Vec::new(),
        };

        let mut root = User {
            username: String::from("root"),
            permissions: Permissions{ allowed_commands: Vec::new() },
        };
        root.permissions.allowed_commands.push(String::from("*"));
        s.allowed_users.push(root);

        s
    }

    pub fn from_file(path: &str) -> Result<Settings, Box<Error>> {
        // Read the file
        //let mut f: File = try!(File::open(path).map_err(|e| Err(e)));
        let mut f: File = File::open(path)?;
        let mut buf: String = String::new();
        f.read_to_string(&mut buf)?;

        // Create a Settings struct from the data
        let settings: Settings = serde_json::from_str(&buf)?;

        // Return newly created settings struct
        Ok(settings)
    }

    pub fn to_string(&self) -> Result<String, Box<Error>> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn get_user(&self, username: &str) -> Result<&User, Box<Error>> {
        let mut user: Result<&User, Box<Error>> = Err(From::from("User not in configuration file!"));
        for u in &self.allowed_users {
            if username == u.username {
                user = Ok(u);
            }
        }
        user
    }

    pub fn can_run_command(&self, username: &str, command: &str) -> Result<bool, Box<Error>> {
        // Find the user's config entry
        let user: &User = self.get_user(username)?;

        // See if the user has permission to run this command
        for perm in &user.permissions.allowed_commands {
            if perm == "*" || perm == command {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // Get the current prompt or return the default if none is present in config
    pub fn get_prompt(&self) -> String {
        self.prompt.clone()
    }
}
