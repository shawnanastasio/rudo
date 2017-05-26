use std::env;
use std::io;
use std::process;
use std::process::Command;
use std::io::Write;
use std::os::unix::process::CommandExt;

mod auth;
use auth::authenticate_current_user_n;
use auth::get_username;

mod settings;
use settings::Settings;

extern crate getopts;
use getopts::Options;
use getopts::ParsingStyle;

extern crate users;
use users::get_user_by_name;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

// Global config
static CONFIG_PATH: &'static str = "/etc/rudo.json";
static DEFAULT_PROMPT: &'static str = "Password: ";

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

/**
* Handles listing of current user's permissions to STDOUT
*/
fn list_permissions() {
    // Load the settings file
    let settings = Settings::from_file(CONFIG_PATH)
    .expect("Unable to read configuration file! Run --genconfig.");

    // Get this user's User struct
    let username = get_username();
    let user = settings.get_user(&username);
    if user.is_err() {
        writeln!(&mut io::stderr(),
        "You are not in the rudo.json file! This incident won't be reported.")
        .expect("Failed to write to stderr!");
        process::exit(1);
    }
    let user = user.unwrap();

    // Create a string of all commands the user can run
    let mut all_commands: String = String::new();
    for cmd in &user.permissions.allowed_commands {
        all_commands += cmd;
        all_commands += " ";
    }

    println!("You are allowed to run the following commands: {}", all_commands);
    process::exit(0);
}

/**
 * Handles default behavior of program - Authenticate and run a command
 * @param user user to run command as
 * @param command program to launch
 * @param args arguments to launch the program with
 */
fn run_command(user: Option<String>, command: &str, args: &Vec<String>) {
    // Load the settings file
    let settings = Settings::from_file(CONFIG_PATH)
    .expect("Unable to read configuration file! Run --genconfig.");

    // Give the user 3 tries to authenticate
    let auth_res = authenticate_current_user_n(&settings, 3);
    if !auth_res {
        process::exit(1);
    }

    // Confirm that user is in the settings file and has permission
    let username: String = get_username();
    let can_run = settings.can_run_command(&username, command);
    if can_run.is_err() {
        writeln!(&mut io::stderr(),
        "You are not in the rudo.json file! This incident won't be reported.")
        .expect("Failed to write to stderr!");
        process::exit(1);
    }
    let can_run = can_run.unwrap();
    if !can_run {
        writeln!(&mut io::stderr(),
        "You don't have permission to run that! This incident won't be reported.")
        .expect("Failed to write to stderr!");
        process::exit(1);
    }

    // Determine the uid of the user to impersonate
    let mut uid: u32 = 0;
    if let Some(username) = user {
        let u = get_user_by_name(&username);
        if u.is_none() {
            writeln!(&mut io::stderr(),
            "Invalid username! See --help for more information.")
            .expect("Failed to write to stderr!");
            process::exit(1);
        }
        uid = u.unwrap().uid();
    }


    // Now that the user is authenticated, run the provided command
    // TODO: Allow impersonating groups other than wheel
    Command::new(command).args(args).uid(uid).gid(0).exec();

    // If we got here, it means the command failed
    writeln!(&mut io::stderr(), "rudo: {}: command not found", &command)
    .expect("Failed to write to stderr!");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program_name = args[0].clone();
    let mut opts = Options::new();
    opts.parsing_style(ParsingStyle::StopAtFirstFree);

    let mut user: Option<String> = None;

    // Set up arguments
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("l", "list", "list all permissions for current user");
    opts.optopt("u", "user", "run as the specified user", "<user>");
    opts.optflag("", "genconfig", "Generate an empty config and output to STDOUT");

    // Create a vec of up to 2 arguments to parse
    // We ignore all arguments past the first
    let mut matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(_) => { print_help(&program_name, opts); process::exit(1); }
    };

    if matches.free.len() < 1 {
        print_help(&program_name, opts);
        process::exit(1);
    }
    
    // Handle help
    if matches.opt_present("h") {
        print_help(&program_name, opts);
        process::exit(0);
    }

    // Handle --list
    if matches.opt_present("l") {
        list_permissions();
        process::exit(0);
    }

    // Handle --user
    if matches.opt_present("u") {
        // Set the user to the provided user
        user = match matches.opt_str("u") {
            Some(x) => Some(x),
            None => { print_help(&program_name, opts); process::exit(1); }
        };
    }

    // Handle --genconfig
    if matches.opt_present("genconfig") {
        generate_empty_config();
        process::exit(0);
    }

    // Handle default behavior (run command)
    let command = matches.free[0].clone();
    let mut command_args = &mut matches.free[0..].to_vec();
    command_args.remove(0);
    run_command(user, &command, &command_args);
}
