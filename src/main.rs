use std::env;
use std::io;
use std::error::Error;
use std::process;
use std::process::Command;
use std::io::Write;
use std::os::unix::process::CommandExt;

mod session;
mod auth;
use auth::authenticate_current_user_n;

mod osutils;
use osutils::OSUtils;
use osutils::unix::UnixOSUtils;

mod settings;
use settings::Settings;

extern crate time;
extern crate rpassword;

extern crate libc;
use libc::isatty;

extern crate getopts;
use getopts::Options;
use getopts::ParsingStyle;


#[macro_use]
extern crate serde_derive;
extern crate serde_json;

// Global config
pub static CONFIG_PATH: &'static str = "/etc/rudo.json";
pub static DEFAULT_PROMPT: &'static str = "Password: ";
pub static SESSION_PATH: &'static str = "/var/run/rudo";
pub static DEFAULT_SESSION_TIMEOUT: i64 = 900;

fn print_help(program_name: &str, opts: Options) {
    let brief = format!("Usage: {} [flags] [command]", program_name);
    writeln!(&mut io::stderr(), "{}", opts.usage(&brief))
        .expect("Failed to write to stderr!");
}

fn generate_empty_config() {
    // Create a new settings object
    let new_settings = Settings::new();

    // Get a serialized string representation of the object
    let settings_str = new_settings.to_string()
        .expect("Unable to generate empty settings file!");

    // Output the new settings string to stdout
    println!("{}", settings_str);
}

///
/// Handles listing of current user's permissions to STDOUT
///
fn list_permissions<T: OSUtils>(osutils: &T) -> Result<i32, Box<Error>> {
    // Load the settings file
    let settings = Settings::from_file(CONFIG_PATH)
        .expect("Unable to read configuration file! Run --genconfig.");

    // Give the user 3 tries to authenticate
    let auth_res = authenticate_current_user_n::<T>(osutils, &settings, 3)?;
    if !auth_res {
        return Ok(1);
    }

    // Get this user's User struct
    let username = osutils.get_username()?;
    let user = settings.get_user(&username)?;

    // Create a string of all commands the user can run
    let mut all_commands: String = String::new();
    for cmd in &user.permissions.allowed_commands {
        all_commands += cmd;
        all_commands += " ";
    }

    println!("You are allowed to run the following commands: {}", all_commands);
    process::exit(0);
}

/// Handles default behavior of program - Authenticate and run a command
/// @param user user to run command as
/// @param command program to launch
/// @param args arguments to launch the program with
/// @return program return code
fn run_command<T: OSUtils>(osutils: &T, user: Option<String>, group: Option<String>,  command: &str, args: &Vec<String>)
    -> Result<i32, Box<Error>> {

    // Load the settings file
    let settings = Settings::from_file(CONFIG_PATH)
        .expect("Unable to read configuration file! Run --genconfig.");

    // Give the user 3 tries to authenticate
    let auth_res = authenticate_current_user_n::<T>(osutils, &settings, 3)?;
    if !auth_res {
        return Ok(1);
    }

    // Confirm that user is in the settings file and has permission
    let username: String = osutils.get_username()?;
    let can_run = settings.can_run_command(&username, command).unwrap_or_else(|_| {
        writeln!(&mut io::stderr(), "You are not in the rudo.json file!").unwrap();
        return false;
    });

    if !can_run {
        writeln!(&mut io::stderr(), "You don't have permission to run that! This incident won't be reported.")
            .unwrap();
        return Ok(1);
    }

    // Determine the uid of the user to impersonate
    let mut uid: u32 = 0;
    let mut gid: u32 = 0;
    if let Some(username) = user {
        let uidgid = osutils.get_uidgid_by_username(&username)?;
        uid = uidgid.0;
        gid = uidgid.1;
    }


    // If the user provided a group, set that
    if let Some(groupname) = group {
    	gid = osutils.get_gid_by_groupname(&groupname)?;
    }


    // Now that the user is authenticated, run the provided command
    Command::new(command).args(args).uid(uid).gid(gid).exec();

    // If we got here, it means the command failed
    writeln!(&mut io::stderr(), "rudo: {}: command not found", &command).unwrap();
    Ok(1)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program_name = args[0].clone();
    let mut opts = Options::new();
    opts.parsing_style(ParsingStyle::StopAtFirstFree);

    let mut user: Option<String> = None;
    let mut group: Option<String> = None;

    // Set up arguments
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("l", "list", "list all permissions for current user");
    opts.optopt("u", "user", "run as the specified user", "<user>");
    opts.optopt("g", "group", "run as the specified group", "<group>");
    opts.optflag("", "genconfig", "Generate an empty config and output to STDOUT");

    // Instantiate platform OSUtils
    let osutils = UnixOSUtils::new();

    // Create a vec of up to 2 arguments to parse
    // We ignore all arguments past the first
    let mut matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(_) => { print_help(&program_name, opts); process::exit(1); }
    };

    // Handle help
    if matches.opt_present("h") {
        print_help(&program_name, opts);
        process::exit(0);
    }

    // Handle --list
    if matches.opt_present("l") {
        let res = list_permissions(&osutils).unwrap_or_else(|e|{
            writeln!(&mut io::stderr(), "Failed to list permissions: {}", e).unwrap();
            process::exit(1);
        });
        process::exit(res);
    }

    // Handle --genconfig
    if matches.opt_present("genconfig") {
        generate_empty_config();
        process::exit(0);
    }

    if matches.free.len() < 1 {
        print_help(&program_name, opts);
        process::exit(1);
    }

    // Handle --user
    if matches.opt_present("u") {
        // Set the user to the provided user
        user = match matches.opt_str("u") {
            Some(x) => Some(x),
            None => { print_help(&program_name, opts); process::exit(1); }
        };
    }

    // Handle --group
    if matches.opt_present("g") {
    	// Set the group to the provided group
    	group = match matches.opt_str("g") {
    		Some(x) => Some(x),
    		None => { print_help(&program_name, opts); process::exit(1) }
    	};
    }

    // Handle default behavior (run command)

    // Make sure we're running in a tty
    let is_tty = unsafe { isatty(0) };
    if is_tty != 1 {
        writeln!(&mut io::stderr(), "rudo must be run from a TTY!").unwrap();
    }
    let command = matches.free[0].clone();
    matches.free.remove(0);
    let res = run_command(&osutils, user, group, &command, &matches.free).unwrap_or_else(|e| {
        writeln!(&mut io::stderr(), "Failed to run command: {}", e).unwrap();
        process::exit(1);
    });

    process::exit(res);
}
