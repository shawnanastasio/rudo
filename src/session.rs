//!
//! Support for user sessions
//!

use std::io;
use std::fs;
use std::process;
use std::ffi::CStr;
use std::fs::File;
use std::error::Error;
use std::io::Write;
use std::io::Read;
use std::path::Path;
use std::fs::DirBuilder;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::DirBuilderExt;

use time;
use serde_json;

use libc::ttyname;

use SESSION_PATH;

/// Struct defining a single user session
#[derive(Serialize, Deserialize)]
struct Session {
    ttyname: String,       // Name of tty that session is valid for
    start_timestamp: i64,  // UNIX Timestamp that session was started at
    end_timestamp: i64,    // UNIX Timestamp that session should expire at
}


/// Safe wrapper to get the name of the current ttyname
/// and return as a Rust string
fn get_cur_tty_name() -> Result<String, Box<Error>> {
    unsafe {
        let ttyname_c = ttyname(0);
        // Verify that call didn't fail
        if ttyname_c.is_null() {
            return Err(From::from("ttyname() call failed!"));
        }
        let ttyname_rust = CStr::from_ptr(ttyname_c).to_string_lossy().into_owned();
        Ok(ttyname_rust)
    }
}

/// Initalize the session directory if it doesn't exist.
/// Quits if the session directory can't be read from/written to
/// or if the correct permissions can't be set.
fn init_session_dir(username: &str) {
    // Create the session directory if it does not exist
    let session_path = Path::new(SESSION_PATH);
    if !session_path.exists() {
        DirBuilder::new().mode(0o600).create(session_path).unwrap_or_else(|_| {
            writeln!(&mut io::stderr(), "Failed to create session directory with correct permissions!")
                .unwrap();
            process::exit(1);
        });
    } else if !session_path.is_dir() {
        writeln!(&mut io::stderr(), "Session path {} should be a directory! Aborting.", SESSION_PATH)
            .unwrap();
        process::exit(1);
    }

    // Make sure the directory has the correct permissions
    let metadata = fs::metadata(SESSION_PATH).unwrap();
    let mut permissions = metadata.permissions();
    if permissions.mode() != 0o600 {
        // The directory doesn't have the correct permissions, set them
        permissions.set_mode(0o600);
        fs::set_permissions(SESSION_PATH, permissions).unwrap();
    }
    // TODO: recursively verify permissions of files in SESSION_PATH

    // Create the user's subdirectory if it doesn't exist
    let user_sub_path_str = format!("{}/{}", SESSION_PATH, username);
    let user_sub_path = Path::new(&user_sub_path_str);
    if !user_sub_path.exists() {
        DirBuilder::new().mode(0o600).create(user_sub_path).unwrap_or_else(|_| {
            writeln!(&mut io::stderr(), "Failed to create user session subdirectory!")
                .unwrap();
            process::exit(1);
        });
    } else if !user_sub_path.is_dir() {
        writeln!(&mut io::stderr(), "User session subdirectory {} is not a directory! Aborting.",
                 user_sub_path_str).unwrap();
        process::exit(1);
    }
}

/// Find a session for the given user and ttyname
/// Also deletes all expired sessions for the user
fn find_user_session(username: &str, ttyname: &str) -> Result<Option<Session>, Box<Error>> {
    let user_sub_path_str = format!("{}/{}", SESSION_PATH, username);
    let user_sub_path = Path::new(&user_sub_path_str);
    if !user_sub_path.exists() || !user_sub_path.is_dir() {
        return Err(From::from("User does not have a session subdirectory!"));
    }

    // Go through all session files in directory
    let mut res: Option<Session> = None;
    let session_files = fs::read_dir(&user_sub_path_str)?;

    for file in session_files {
        // Read the session file into a Session struct
        let file = file?;
        let mut buf = String::new();
        let mut f = File::open(file.path())?;
        f.read_to_string(&mut buf)?;

        let cur_session: Session = serde_json::from_str(&buf)?;

        // Delete the session if it has expired
        let cur_timestamp = time::get_time().sec;
        if cur_timestamp >= cur_session.end_timestamp {
            // This session is expired, delete it
            fs::remove_file(file.path())?;
            continue;
        }

        // If the session meets the criteria, return it
        if cur_session.ttyname == ttyname {
            res = Some(cur_session);
        }
    }

    Ok(res)
}

/// Checks to see if the user has an active authenticated session.
/// Returns whether the user has an active session or not
pub fn check_session(username: &str) -> Result<bool, Box<Error>> {
    // Make sure the session directory exists and has the correct permissions
    init_session_dir(username);

    // Get the name of the current TTY
    let ttyname = get_cur_tty_name()?;

    // See if the user has a current session
    let session_res = find_user_session(username, &ttyname)?;

    match session_res {
        Some(_) => return Ok(true), // An ongoing session was found
        None => return Ok(false),   // No ongoing session was found
    }
}

/// Create a session for the given user that will last for the given time in seconds
pub fn create_session(username: &str, time: i64) -> Result<(), Box<Error>> {
    // Make sure the user has a session directory and it has the correct permissions
    init_session_dir(username);

    // Get the name of the current TTY
    let ttyname = get_cur_tty_name()?;

    // Create the new session object
    let cur_timestamp = time::get_time().sec;
    let new_session = Session {
        ttyname: ttyname,
        start_timestamp: cur_timestamp,
        end_timestamp: cur_timestamp + time,
    };

    // Until I can think of something more clever, we'll just use the lowest
    // number that's not taken as our filename
    let mut i = 0;
    loop {
        // See if the current number is taken as a filename
        let cur_filename = format!("{}/{}/{}", SESSION_PATH, username, i);
        let cur_path = Path::new(&cur_filename);
        if !cur_path.exists() {
            // The filename isn't taken, let's use it
            let new_session_str = serde_json::to_string(&new_session)?;
            let mut f = File::create(&cur_filename)?;
            f.write_all(new_session_str.as_bytes())?;

            // Set proper permissions (0o600)
            let mut permissions = f.metadata()?.permissions();
            permissions.set_mode(0o600);
            f.set_permissions(permissions)?;

            break;
        }
        i += 1;
    }

    Ok(())
}
