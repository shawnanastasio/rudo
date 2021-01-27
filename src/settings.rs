use std::io::prelude::*;
use std::fs::File;
use std::error::Error;
use std::path::Path;

use serde_json;
use which::which;

use DEFAULT_PROMPT;
use DEFAULT_SESSION_TIMEOUT;

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
    pub session_timeout_sec: i64,
    pub allowed_users: Vec<User>,
}

impl Settings {
    pub fn new() -> Settings {
        // Create an empty Settings struct with `root` as the only user
        let mut s = Settings {
            prompt: String::from(DEFAULT_PROMPT),
            session_timeout_sec: DEFAULT_SESSION_TIMEOUT,
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

    fn validate(&self) -> Option<Box<dyn Error>> {
        // Check that all paths in allowed commands are absolute
        for user in &self.allowed_users {
            for cmd in &user.permissions.allowed_commands {
                if cmd == "*" { continue; }

                if cmd.chars().nth(0).unwrap() != '/' {
                    return Some(From::from("Only absolute paths are allowed in allowed_commands"));
                }
            }
        }
        None
    }

    pub fn from_file(path: &str) -> Result<Settings, Box<dyn Error>> {
        // Read the file
        //let mut f: File = try!(File::open(path).map_err(|e| Err(e)));
        let mut f: File = File::open(path)?;
        let mut buf: String = String::new();
        f.read_to_string(&mut buf)?;

        // Create a Settings struct from the data
        let settings: Settings = serde_json::from_str(&buf)?;

        // Validate struct and return
        match settings.validate() {
            Some(v) => Err(v),
            None => Ok(settings)
        }
    }

    pub fn to_string(&self) -> Result<String, Box<dyn Error>> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn get_user(&self, username: &str) -> Result<&User, Box<dyn Error>> {
        let mut user: Result<&User, Box<dyn Error>> = Err(From::from("User not in configuration file!"));
        for u in &self.allowed_users {
            if username == u.username {
                user = Ok(u);
            }
        }
        user
    }

    pub fn sanitize_user_command(&self, username: &str, command: &str) -> Result<String, Box<dyn Error>> {
        // Find the user's config entry
        let user: &User = self.get_user(username)?;

        // See if the user has permission to run this command
        for perm in &user.permissions.allowed_commands {
            if perm == "*" {
                return Ok(command.to_string());
            }

            let perm_path = Path::new(perm);
            let perm_canonical = match perm_path.canonicalize() {
                Ok(v) => v,
                Err(_) => { continue; }
            };

            if command.contains("/") {
                // If a path was given, canonicalize and check for direct match
                let command_path = Path::new(command);
                let command_canonical = command_path.canonicalize()?;

                if perm_canonical == command_canonical {
                    return Ok(command_canonical.into_os_string().into_string().unwrap());
                }
            } else {
                // If a non-path command name was given, resolve it in PATH and compare
                // the result against the permission's canonical path.
                let command_pathbuf = which(command)?;
                let command_canonical = command_pathbuf.as_path().canonicalize()?;

                if perm_canonical == command_canonical {
                    return Ok(command_canonical.into_os_string().into_string().unwrap());
                }
            }
        }
        Err(From::from("Command not present in `allowed_commands`"))
    }

    // Get the current prompt or return the default if none is present in config
    pub fn get_prompt(&self) -> &String {
        &self.prompt
    }
}
