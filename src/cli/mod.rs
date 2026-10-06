// ============================================================================
//  src/cli/mod.rs  --  argument parsing and subcommand dispatch
// ============================================================================
//
//  EXPERT VIEW:
//    Real Rust CLIs usually use `clap`. We hand-roll the parser instead, for
//    three reasons that are specific to this project:
//
//      1. **Dependency surface.** `otkp serve` runs as root and changes firewall
//         rules. Every crate in its graph is code we must trust. `clap` is
//         excellent and widely used, but "widely used" is not "necessary here".
//      2. **Explicitness.** A hand-rolled parser makes the grammar of the CLI
//         readable in one file, which is a virtue for a tool an operator may need
//         to audit.
//      3. **It is small.** Six subcommands, a dozen flags. That is well within
//         the range where a hand-rolled parser is less code than the glue needed
//         to configure a framework.
//
//    The parser is deliberately *flat*: a single pass that builds a
//    `ParsedArgs` struct of options plus the subcommand. It supports
//    `--flag value` and `--flag=value` and `-v` short forms, because those are
//    the three forms users actually type. It does not support clustering
//    (`-vvv`) or abbreviations, because guessing what the user meant is how
//    CLIs become surprising.
//
//  KID VIEW:
//    This is the front desk. You walk in and say what you want ("serve", "knock",
//    "enroll") and hand over your details ("--user alice", "--server 1.2.3.4").
//    The desk clerk writes it all on a form, and if you said something he does
//    not understand, he tells you plainly instead of guessing.
// ============================================================================

use crate::error::{OtkpError, Result};

// The subcommand modules. Each is small and does exactly one thing.
/// `otkp enroll` -- create a user and print their secret once.
pub mod enroll; // `otkp enroll`
/// `otkp init` -- create the data directory and its files.
pub mod init; //   `otkp init`
/// `otkp knock` -- the client: derive and send a knock sequence.
pub mod knock; //  `otkp knock`   (client)
/// `otkp serve` -- start the daemon.
pub mod serve; //  `otkp serve`   (daemon)
/// `otkp verify` -- print the current sequence, for debugging.
pub mod verify; // `otkp verify`  (debug)

// ===========================================================================
//  Command -- which subcommand was requested
// ===========================================================================
/// The subcommand the user asked for.
///
/// EXPERT: A flat enum with data-carrying variants for the commands that take a
///         required positional argument (`enroll` and `verify` take a user name).
///         Everything optional lives in `Options` below, so the two concerns --
///         "which command" and "with what settings" -- stay separate. That split
///         is why dispatch can be a simple `match` on `command` while every
///         handler reads the same `&Options`.
/// KID: The list of things the front desk knows how to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Create the data directory, config, keyring and ban list.
    Init,
    /// Create a new user enrolment and print their secret once.
    Enroll {
        /// The user name to enrol.
        user: String,
    },
    /// Run the daemon.
    Serve,
    /// Print the current knock sequence for a user (debugging aid).
    Verify {
        /// The user name to verify.
        user: String,
    },
    /// Derive a sequence for right now and send it (the client).
    Knock,
    /// Print usage.
    Help,
}

// ===========================================================================
//  Options -- every flag, in one place
// ===========================================================================
/// All the command-line options, with defaults.
///
/// EXPERT: One struct for every flag, regardless of which subcommand uses it.
///         The alternative -- a struct per subcommand -- would be more precise
///         but would multiply the parser's match arms by four. Since this struct
///         is small and every field has a documented default, the flat approach
///         keeps the parser honest and readable. Fields that only one subcommand
///         uses are commented as such.
/// KID: The form the desk clerk fills in. Not every line is needed for every
///      request, but they are all on the same sheet.
#[derive(Debug, Clone)]
pub struct Options {
    /// The data directory: where config.json, keyring.json and banlist.json live.
    ///
    /// EXPERT: A `String`, not a `PathBuf`, because it comes straight from argv
    ///         and we want to echo it back verbatim in error messages. Handlers
    ///         convert it to `PathBuf` at the point of use. `/etc/otkp` is the
    ///         conventional location and the default.
    /// KID: The folder where we keep all our important papers.
    pub dir: String,

    /// How loud to log. Set from `-v`/`--verbose` and `-q`/`--quiet`.
    pub verbosity: crate::logging::Level,

    // ---- `enroll` and `verify` ----
    /// The user name (positional for `enroll` and `verify`).
    pub user: Option<String>,

    // ---- `knock` (client) ----
    /// The server's hostname or IP.
    pub server: Option<String>,
    /// The server's UDP listener port.
    pub port: Option<u16>,
    /// The user's secret, as base32 or hex text.
    pub secret: Option<String>,
    /// Transport mode: "udp" or "raw".
    pub mode: Option<String>,
    /// Time-step offset to try (-1, 0 or +1), for clock-skew workarounds.
    pub step_offset: i64,
    /// The address the server will observe, for source-bound derivations.
    pub bind_ip: Option<String>,

    // ---- `serve` (daemon) ----
    /// Which firewall backend to use.
    pub firewall: Option<String>,
    /// Which knock source to use ("udp" or "raw").
    pub source: Option<String>,
    /// Seconds per time window (overrides the config file).
    pub step_seconds: Option<u64>,
    /// Failures inside the rolling window before a ban (overrides the config).
    pub ban_fail_threshold: Option<u32>,
    /// Length of the rolling failure window, in seconds.
    pub ban_window_seconds: Option<u64>,
    /// Seconds an opened port stays open.
    pub open_ttl: Option<u64>,
    /// Seconds a ban lasts (0 = permanent).
    pub ban_ttl: Option<u64>,
    /// Milliseconds between knocks the client should use.
    pub inter_knock_delay_ms: Option<u64>,

    // ---- `init` ----
    /// Overwrite an existing configuration.
    pub force: bool,

    // ---- testing / operations ----
    /// Run at most this many loop iterations, then exit. Used by the
    /// integration tests and by `--once` smoke runs.
    pub max_iterations: Option<u64>,
}

impl Default for Options {
    /// Sensible defaults for every flag.
    ///
    /// EXPERT: `Default` for an options struct is a genuine convenience: the
    ///         parser starts from `Default::default()` and overwrites only the
    ///         fields it sees, so adding a new flag requires touching exactly two
    ///         places (the struct and the parser arm), never the initialiser.
    /// KID: The form comes pre-filled with the usual answers.
    fn default() -> Self {
        Options {
            dir: "/etc/otkp".to_string(),
            verbosity: crate::logging::Level::Info,
            user: None,
            server: None,
            port: None,
            secret: None,
            mode: None,
            step_offset: 0,
            bind_ip: None,
            firewall: None,
            source: None,
            step_seconds: None,
            ban_fail_threshold: None,
            ban_window_seconds: None,
            open_ttl: None,
            ban_ttl: None,
            inter_knock_delay_ms: None,
            force: false,
            max_iterations: None,
        }
    }
}

// ===========================================================================
//  The parser
// ===========================================================================
/// The result of parsing argv: a command plus its options.
#[derive(Debug, Clone)]
pub struct ParsedArgs {
    /// Which subcommand to run.
    pub command: Command,
    /// All the flags.
    pub options: Options,
}

/// Parse a full argv (excluding the program name).
///
/// EXPERT: The parser is a single left-to-right pass with a tiny state machine:
///         "am I expecting a value for the previous flag?" That is expressed as
///         an `Option<&str>` holding the flag name awaiting a value, which is far
///         simpler than an index-based loop and makes `--flag value` fall out
///         naturally.
///
/// Positional arguments are collected separately. Only `enroll` and
///         `verify` take one, and only one, so we check that at the end rather
///         than trying to be clever during the scan.
///
/// Errors name the offending token. "unknown flag '--ban-treshold'" with
///         the typo highlighted is worth a hundred lines of help text.
/// KID: Read the form the person handed you, line by line, and check every line
///      makes sense.
pub fn parse<I, S>(args: I) -> Result<ParsedArgs>
where
    // `I: IntoIterator<Item = S>` is the idiomatic "anything iterable of
    // anything string-like" bound. It lets callers pass `env::args().skip(1)`,
    // a `Vec<String>`, or an array of `&str` in tests.
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    // Collect into owned Strings so we can hold references into the vec.
    let args: Vec<String> = args.into_iter().map(Into::into).collect();

    let mut options = Options::default();
    // The subcommand, once we see the first non-flag argument.
    let mut command: Option<Command> = None;
    // Positional arguments after the subcommand (at most one is used).
    let mut positionals: Vec<String> = Vec::new();
    // If Some(name), the next argument is that flag's value.
    let mut expecting_value_for: Option<String> = None;

    for arg in args {
        // --------------------------------------------------------------
        // Case 1: we are waiting for the value of a previous flag.
        // --------------------------------------------------------------
        if let Some(flag) = expecting_value_for.take() {
            apply_flag_value(&mut options, &flag, &arg)?;
            continue;
        }

        // --------------------------------------------------------------
        // Case 2: a long flag, `--name` or `--name=value`.
        // --------------------------------------------------------------
        if let Some(rest) = arg.strip_prefix("--") {
            // Split on '=' to support the `--name=value` form.
            match rest.split_once('=') {
                // `--name=value`: apply immediately.
                Some((name, value)) => {
                    let flag = format!("--{name}");
                    apply_flag_value(&mut options, &flag, value)?;
                }
                // `--name` alone: it may need a value, so defer.
                None => {
                    let flag = format!("--{rest}");
                    // `--help` anywhere wins immediately, before we try to
                    // classify it.
                    if flag == "--help" {
                        return Ok(ParsedArgs {
                            command: Command::Help,
                            options,
                        });
                    }
                    // Boolean flags are applied immediately; value flags defer.
                    if is_boolean_flag(&flag) {
                        apply_boolean_flag(&mut options, &flag)?;
                    } else if is_known_value_flag(&flag) {
                        expecting_value_for = Some(flag);
                    } else {
                        return Err(unknown_flag(&flag));
                    }
                }
            }
            continue;
        }

        // --------------------------------------------------------------
        // Case 3: a short flag, `-v`, `-q`, `-f`.
        // --------------------------------------------------------------
        if arg.starts_with('-') && arg.len() > 1 {
            match arg.as_str() {
                "-v" | "--verbose" => options.verbosity = crate::logging::Level::Debug,
                "-q" | "--quiet" => options.verbosity = crate::logging::Level::Warn,
                "-f" | "--force" => options.force = true,
                "-h" | "--help" => {
                    // `--help` anywhere wins immediately.
                    return Ok(ParsedArgs {
                        command: Command::Help,
                        options,
                    });
                }
                other => return Err(unknown_flag(other)),
            }
            continue;
        }

        // --------------------------------------------------------------
        // Case 4: a bare word. The first one is the subcommand; later ones
        // are positionals.
        // --------------------------------------------------------------
        if command.is_none() {
            command = Some(parse_command(&arg)?);
        } else {
            positionals.push(arg);
        }
    }

    // A trailing `--flag` with no value is a user error worth naming precisely.
    if let Some(flag) = expecting_value_for {
        return Err(OtkpError::config(format!(
            "flag '{flag}' requires a value (use '{flag} value' or '{flag}=value')"
        )));
    }

    // Default to Help when no subcommand was given, which prints usage. That is
    // friendlier than an error: a bare `otkp` almost always means "tell me how".
    let mut command = command.unwrap_or(Command::Help);

    // ----------------------------------------------------------------
    // Attach positionals to the commands that take one.
    // ----------------------------------------------------------------
    match &mut command {
        Command::Enroll { user } | Command::Verify { user } => {
            // Prefer an explicit positional; fall back to `--user`.
            let chosen = positionals
                .first()
                .cloned()
                .or_else(|| options.user.clone());
            match chosen {
                Some(u) => {
                    *user = u.clone();
                    options.user = Some(u);
                }
                None => return Err(OtkpError::config(
                    "this command needs a user name (e.g. `otkp enroll alice` or `--user alice`)",
                )),
            }
            // Reject surplus positionals rather than silently ignoring them.
            if positionals.len() > 1 {
                return Err(OtkpError::config(format!(
                    "unexpected extra argument '{}'",
                    positionals[1]
                )));
            }
        }
        _ => {
            // No other command takes positionals.
            if let Some(extra) = positionals.first() {
                return Err(OtkpError::config(format!("unexpected argument '{extra}'")));
            }
        }
    }

    Ok(ParsedArgs { command, options })
}

/// Build the "unknown flag" error, with a suggestion when we can guess one.
///
/// EXPERT: A tiny Levenshtein-ish suggestion (we use a cheap "starts with the
///         same three characters" heuristic rather than a full edit-distance
///         implementation) turns a frustrating error into a helpful one. The
///         cost is a dozen lines; the benefit is that a typo like
///         `--ban-fail-treshold` points straight at `--ban-fail-threshold`.
/// KID: "I do not know that word -- did you mean this one?"
fn unknown_flag(flag: &str) -> OtkpError {
    // The complete set of flags we know, for suggestion purposes.
    const KNOWN: &[&str] = &[
        "--dir",
        "--user",
        "--server",
        "--port",
        "--secret",
        "--mode",
        "--step-offset",
        "--bind-ip",
        "--firewall",
        "--source",
        "--step-seconds",
        "--ban-fail-threshold",
        "--ban-window",
        "--open-ttl",
        "--ban-ttl",
        "--inter-knock-delay-ms",
        "--max-iterations",
        "--verbose",
        "--quiet",
        "--force",
        "--help",
    ];

    // Find candidates that share a prefix of at least 3 characters after the
    // leading dashes. Cheap, and good enough to catch the common typos.
    let needle = flag.trim_start_matches('-');
    let prefix: String = needle.chars().take(3).collect();
    let suggestion = KNOWN.iter().find(|k| {
        k.trim_start_matches('-')
            .to_lowercase()
            .starts_with(&prefix.to_lowercase())
    });

    match suggestion {
        Some(s) => OtkpError::config(format!("unknown flag '{flag}' (did you mean '{s}'?)")),
        None => OtkpError::config(format!("unknown flag '{flag}' (try `otkp help`)")),
    }
}

/// Does this flag take a value?
///
/// EXPERT: A hard-coded list, checked before we decide whether to consume the
///         next argument. This is the crux of a hand-rolled parser: without it,
///         `otkp knock --server` would silently swallow the subcommand, or worse,
///         `--force` would eat a following positional. Being explicit here is
///         what keeps the parser predictable.
/// KID: A list of the questions that need an answer, versus the on/off switches.
fn is_known_value_flag(flag: &str) -> bool {
    matches!(
        flag,
        "--dir"
            | "--user"
            | "--server"
            | "--port"
            | "--secret"
            | "--mode"
            | "--step-offset"
            | "--bind-ip"
            | "--firewall"
            | "--source"
            | "--step-seconds"
            | "--ban-fail-threshold"
            | "--ban-window"
            | "--open-ttl"
            | "--ban-ttl"
            | "--inter-knock-delay-ms"
            | "--max-iterations"
    )
}

/// Is this flag a simple on/off switch?
fn is_boolean_flag(flag: &str) -> bool {
    matches!(flag, "--force" | "--verbose" | "--quiet" | "--help")
}

/// Apply a boolean flag.
fn apply_boolean_flag(options: &mut Options, flag: &str) -> Result<()> {
    match flag {
        "--force" => options.force = true,
        "--verbose" => options.verbosity = crate::logging::Level::Debug,
        "--quiet" => options.verbosity = crate::logging::Level::Warn,
        // `--help` is handled by the caller (it short-circuits), but we accept it
        // here too so the function is total over `is_boolean_flag`'s set.
        "--help" => {}
        other => return Err(unknown_flag(other)),
    }
    Ok(())
}

/// Parse a flag's value and store it.
///
/// EXPERT: One arm per flag. Note that every numeric parse uses a helper
///         (`parse_u16`, `parse_u64`, `parse_i64`) that produces a *named* error
///         including the offending value, rather than the bare
///         `ParseIntError` you would get from `.parse().unwrap()`. Error quality
///         is a feature, and this is where it is cheapest to provide.
/// KID: Take the answer the person gave and write it in the right box on the
///      form, checking it is the right kind of answer.
fn apply_flag_value(options: &mut Options, flag: &str, value: &str) -> Result<()> {
    match flag {
        "--dir" => options.dir = value.to_string(),
        "--user" => options.user = Some(value.to_string()),
        "--server" => options.server = Some(value.to_string()),
        "--port" => options.port = Some(parse_u16(flag, value)?),
        "--secret" => options.secret = Some(value.to_string()),
        "--mode" => options.mode = Some(value.to_string()),
        "--step-offset" => options.step_offset = parse_i64(flag, value)?,
        "--bind-ip" => options.bind_ip = Some(value.to_string()),
        "--firewall" => options.firewall = Some(value.to_string()),
        "--source" => options.source = Some(value.to_string()),
        "--step-seconds" => options.step_seconds = Some(parse_u64(flag, value)?),
        "--ban-fail-threshold" => options.ban_fail_threshold = Some(parse_u32(flag, value)?),
        "--ban-window" => options.ban_window_seconds = Some(parse_u64(flag, value)?),
        "--open-ttl" => options.open_ttl = Some(parse_u64(flag, value)?),
        "--ban-ttl" => options.ban_ttl = Some(parse_u64(flag, value)?),
        "--inter-knock-delay-ms" => options.inter_knock_delay_ms = Some(parse_u64(flag, value)?),
        "--max-iterations" => options.max_iterations = Some(parse_u64(flag, value)?),
        other => return Err(unknown_flag(other)),
    }
    Ok(())
}

/// Parse a `u16` with a named error.
fn parse_u16(flag: &str, value: &str) -> Result<u16> {
    value.parse::<u16>().map_err(|_| {
        OtkpError::config(format!(
            "flag '{flag}' expects a number between 0 and 65535, got '{value}'"
        ))
    })
}

/// Parse a `u32` with a named error.
fn parse_u32(flag: &str, value: &str) -> Result<u32> {
    value.parse::<u32>().map_err(|_| {
        OtkpError::config(format!(
            "flag '{flag}' expects a non-negative number, got '{value}'"
        ))
    })
}

/// Parse a `u64` with a named error.
fn parse_u64(flag: &str, value: &str) -> Result<u64> {
    value.parse::<u64>().map_err(|_| {
        OtkpError::config(format!(
            "flag '{flag}' expects a non-negative number, got '{value}'"
        ))
    })
}

/// Parse an `i64` (for `--step-offset`, which may be negative).
fn parse_i64(flag: &str, value: &str) -> Result<i64> {
    value.parse::<i64>().map_err(|_| {
        OtkpError::config(format!(
            "flag '{flag}' expects a whole number, got '{value}'"
        ))
    })
}

/// Map a bare word to a `Command`.
///
/// EXPERT: We accept a few aliases (`ls` for `list`-ish, `client` for `knock`)
///         because muscle memory from other tools is real. We reject everything
///         else loudly. Note `help` is a command as well as a flag, because both
///         `otkp help` and `otkp --help` are natural things to type.
/// KID: Translate the word the person said into the job we know how to do.
fn parse_command(word: &str) -> Result<Command> {
    match word {
        "init" => Ok(Command::Init),
        // `enroll` and `verify` get their user name later, from a positional.
        "enroll" | "add" => Ok(Command::Enroll {
            user: String::new(),
        }),
        "serve" | "daemon" | "server" => Ok(Command::Serve),
        "verify" | "show" => Ok(Command::Verify {
            user: String::new(),
        }),
        "knock" | "client" | "connect" => Ok(Command::Knock),
        "help" | "--help" | "-h" => Ok(Command::Help),
        other => Err(OtkpError::config(format!(
            "unknown command '{other}' (try `otkp help`)"
        ))),
    }
}

// ===========================================================================
//  Dispatch
// ===========================================================================
/// Run the command the user asked for.
///
/// EXPERT: The top-level dispatch. Each arm delegates immediately to a function
///         in a submodule, so this file stays a table of contents. That is the
///         same top-down discipline as `lib.rs`: the highest-level function
///         tells you the shape of the whole CLI in six lines.
/// KID: The front desk reads the form and sends you to the right office.
pub fn run(parsed: ParsedArgs) -> Result<()> {
    // Apply the verbosity before anything else can log.
    crate::logging::set_verbosity(parsed.options.verbosity);

    match parsed.command {
        Command::Init => init::run(&parsed.options),
        Command::Enroll { user } => enroll::run(&parsed.options, &user),
        Command::Serve => serve::run(&parsed.options),
        Command::Verify { user } => verify::run(&parsed.options, &user),
        Command::Knock => knock::run(&parsed.options),
        Command::Help => {
            print_help();
            Ok(())
        }
    }
}

/// Print the usage text.
///
/// EXPERT: A `&'static str` returned from a function, printed with `print!`
///         (stdout, not stderr) because help is the *requested output* of
///         `otkp help`. Errors go to stderr; requested output goes to stdout.
///         That distinction is what makes `otkp help | less` work.
/// KID: The instructions poster on the wall.
pub fn print_help() {
    // `concat!` glues string literals at compile time, so there is no runtime
    // allocation and no risk of a typo in a `\n` escape.
    print!(
        "{}",
        concat!(
            "otkp -- One Time Knock Protocol\n",
            "\n",
            "USAGE:\n",
            "  otkp <COMMAND> [OPTIONS]\n",
            "\n",
            "SERVER COMMANDS:\n",
            "  init      [--dir DIR] [--force]\n",
            "            Create DIR, config.json, keyring.json and banlist.json.\n",
            "\n",
            "  enroll    <USER> [--dir DIR]\n",
            "            Create a new user and print their secret ONCE.\n",
            "\n",
            "  serve     [--dir DIR] [--firewall MODE] [--source MODE]\n",
            "            [--ban-fail-threshold N] [--ban-window SECS]\n",
            "            Run the daemon. Firewall modes: dry-run (default),\n",
            "            iptables, nftables, command. Sources: udp (default), raw.\n",
            "\n",
            "  verify    <USER> [--dir DIR]\n",
            "            Print the knock sequence for the current time window.\n",
            "\n",
            "CLIENT COMMANDS:\n",
            "  knock     --server HOST --user USER --secret SECRET [--port P]\n",
            "            [--mode udp|raw] [--step-offset -1|0|1]\n",
            "            Derive the sequence for now and send it.\n",
            "\n",
            "GLOBAL OPTIONS:\n",
            "  -v, --verbose          Log every observed packet.\n",
            "  -q, --quiet            Only log warnings and errors.\n",
            "  -h, --help             Show this help.\n",
            "\n",
            "EXAMPLES:\n",
            "  sudo otkp init --dir /etc/otkp\n",
            "  sudo otkp enroll alice --dir /etc/otkp\n",
            "  sudo otkp serve --dir /etc/otkp --firewall dry-run\n",
            "  otkp knock --server vps.example.com --user alice --secret JBSW...\n",
            "\n",
            "See README.md and docs/PROTOCOL.md for the full story.\n",
        )
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Parse from a slice of string literals.
    fn parse_str(args: &[&str]) -> Result<ParsedArgs> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn bare_invocation_shows_help() {
        let p = parse_str(&[]).unwrap();
        assert_eq!(p.command, Command::Help);
    }

    #[test]
    fn help_flag_shows_help() {
        assert_eq!(parse_str(&["--help"]).unwrap().command, Command::Help);
        assert_eq!(parse_str(&["-h"]).unwrap().command, Command::Help);
        assert_eq!(parse_str(&["help"]).unwrap().command, Command::Help);
    }

    #[test]
    fn init_parses_dir_and_force() {
        let p = parse_str(&["init", "--dir", "/tmp/otkp-test", "--force"]).unwrap();
        assert_eq!(p.command, Command::Init);
        assert_eq!(p.options.dir, "/tmp/otkp-test");
        assert!(p.options.force);
    }

    #[test]
    fn equals_form_works() {
        let p = parse_str(&["init", "--dir=/tmp/x"]).unwrap();
        assert_eq!(p.options.dir, "/tmp/x");
    }

    #[test]
    fn enroll_takes_a_positional_user() {
        let p = parse_str(&["enroll", "alice"]).unwrap();
        assert_eq!(
            p.command,
            Command::Enroll {
                user: "alice".to_string()
            }
        );
        // The options struct is kept in sync so handlers can read either.
        assert_eq!(p.options.user.as_deref(), Some("alice"));
    }

    #[test]
    fn enroll_accepts_the_user_flag_instead() {
        let p = parse_str(&["enroll", "--user", "bob"]).unwrap();
        assert_eq!(
            p.command,
            Command::Enroll {
                user: "bob".to_string()
            }
        );
    }

    #[test]
    fn enroll_without_a_user_is_an_error() {
        let err = parse_str(&["enroll"]).unwrap_err();
        assert!(err.to_string().contains("needs a user name"));
    }

    #[test]
    fn verify_parses_a_user() {
        let p = parse_str(&["verify", "carol", "--dir", "/etc/otkp"]).unwrap();
        assert_eq!(
            p.command,
            Command::Verify {
                user: "carol".to_string()
            }
        );
    }

    #[test]
    fn knock_parses_all_client_flags() {
        let p = parse_str(&[
            "knock",
            "--server",
            "vps.example.com",
            "--port",
            "62201",
            "--user",
            "alice",
            "--secret",
            "JBSWY3DP",
            "--mode",
            "raw",
            "--step-offset",
            "-1",
        ])
        .unwrap();
        assert_eq!(p.command, Command::Knock);
        assert_eq!(p.options.server.as_deref(), Some("vps.example.com"));
        assert_eq!(p.options.port, Some(62201));
        assert_eq!(p.options.user.as_deref(), Some("alice"));
        assert_eq!(p.options.secret.as_deref(), Some("JBSWY3DP"));
        assert_eq!(p.options.mode.as_deref(), Some("raw"));
        // A negative offset must parse, which is why it is an i64.
        assert_eq!(p.options.step_offset, -1);
    }

    #[test]
    fn serve_parses_daemon_flags() {
        let p = parse_str(&[
            "serve",
            "--firewall",
            "iptables",
            "--source",
            "raw",
            "--ban-fail-threshold",
            "3",
            "--ban-window",
            "600",
            "--open-ttl",
            "60",
            "--ban-ttl",
            "0",
        ])
        .unwrap();
        assert_eq!(p.command, Command::Serve);
        assert_eq!(p.options.firewall.as_deref(), Some("iptables"));
        assert_eq!(p.options.source.as_deref(), Some("raw"));
        assert_eq!(p.options.ban_fail_threshold, Some(3));
        assert_eq!(p.options.ban_window_seconds, Some(600));
        assert_eq!(p.options.open_ttl, Some(60));
        assert_eq!(p.options.ban_ttl, Some(0));
    }

    #[test]
    fn verbose_and_quiet_set_verbosity() {
        let p = parse_str(&["serve", "-v"]).unwrap();
        assert_eq!(p.options.verbosity, crate::logging::Level::Debug);
        let p = parse_str(&["serve", "-q"]).unwrap();
        assert_eq!(p.options.verbosity, crate::logging::Level::Warn);
    }

    #[test]
    fn unknown_command_is_rejected() {
        let err = parse_str(&["frobnicate"]).unwrap_err();
        assert!(err.to_string().contains("unknown command"));
    }

    #[test]
    fn unknown_flag_suggests_a_close_match() {
        let err = parse_str(&["serve", "--ban-fail-treshold", "3"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown flag"));
        // The suggestion should point at the real flag name.
        assert!(msg.contains("--ban-fail-threshold"), "got: {msg}");
    }

    #[test]
    fn missing_flag_value_is_reported() {
        let err = parse_str(&["serve", "--firewall"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn bad_number_is_reported_with_the_flag_name() {
        let err = parse_str(&["serve", "--open-ttl", "soon"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--open-ttl"));
        assert!(msg.contains("soon"));
    }

    #[test]
    fn port_out_of_range_is_rejected() {
        // 70000 does not fit in a u16.
        let err = parse_str(&["knock", "--port", "70000"]).unwrap_err();
        assert!(err.to_string().contains("65535"));
    }

    #[test]
    fn extra_positional_is_rejected() {
        let err = parse_str(&["enroll", "alice", "bob"]).unwrap_err();
        assert!(err.to_string().contains("extra argument"));
    }

    #[test]
    fn extra_positional_on_a_flagless_command_is_rejected() {
        let err = parse_str(&["serve", "extra"]).unwrap_err();
        assert!(err.to_string().contains("unexpected argument"));
    }

    #[test]
    fn command_aliases_work() {
        assert_eq!(parse_str(&["daemon"]).unwrap().command, Command::Serve);
        assert_eq!(parse_str(&["client"]).unwrap().command, Command::Knock);
        assert_eq!(
            parse_str(&["add", "x"]).unwrap().command,
            Command::Enroll {
                user: "x".to_string()
            }
        );
    }

    #[test]
    fn max_iterations_parses() {
        // Used by the integration tests to bound the daemon loop.
        let p = parse_str(&["serve", "--max-iterations", "5"]).unwrap();
        assert_eq!(p.options.max_iterations, Some(5));
    }
}
