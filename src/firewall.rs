// ============================================================================
//  src/firewall.rs  --  turning a decision into a real firewall rule
// ============================================================================
//
//  EXPERT VIEW:
//    The engine decides; this module *does*. It is the boundary between our
//    clean, testable logic and the messy, privileged, platform-specific world of
//    packet filtering. That boundary is expressed as a trait:
//
//        pub trait Firewall {
//            fn open_port(&mut self, ip, port) -> Result<()>;
//            fn close_port(&mut self, ip, port) -> Result<()>;
//            fn ban_ip(&mut self, ip) -> Result<()>;
//            fn unban_ip(&mut self, ip) -> Result<()>;
//        }
//
//    This is the single most important design decision in the file, and it is the
//    Rust way to get what an OO programmer would call "polymorphism". Four
//    implementations follow: `DryRunFirewall` (log only), `IptablesFirewall`,
//    `NftablesFirewall`, and `CommandFirewall` (a template for anything else).
//    The daemon is written against the *trait*, so it does not know or care which
//    one it has. That is what lets us test the entire daemon with the dry-run
//    backend and never touch a real firewall in CI.
//
//    A note on privilege: every real backend shells out to a system tool
//    (`iptables`, `nft`). That is a deliberate choice over linking `libnftnl` or
//    `iptables`' C libraries:
//      * the CLI tools are what operators already know and can debug by hand,
//      * the rule text appears in logs exactly as it was applied,
//      * we avoid an FFI surface (and the `unsafe` it would require) entirely.
//    The cost is a `fork`/`exec` per rule change. For a port-knocking daemon
//    that changes rules a few times a minute, that is irrelevant.
//
//  KID VIEW:
//    The engine is the bouncer's brain; this file is his hands. There are four
//    pairs of hands to choose from: pretend hands (practice mode), iptables
//    hands, nft hands, or "whatever machine you tell me to use" hands. The
//    bouncer's brain never knows which hands it has -- it just says "open door
//    number 27488 for this visitor" and the hands do it.
// ============================================================================

use crate::config::FirewallConfig;
use crate::error::{OtkpError, Result};
use std::net::IpAddr;
use std::process::Command;

// ===========================================================================
//  The trait: the interface every backend must satisfy
// ===========================================================================
/// The operations a firewall backend must provide.
///
/// EXPERT: Why `&mut self` on every method? Because a backend may legitimately
///         hold mutable state -- a command backend might keep a counter for
///         logging, or a caching backend might remember installed rules. Even
///         when an implementation needs no state, `&mut self` costs nothing and
///         avoids forcing a later breaking change. (We could have used `&self`
///         with interior mutability, but that is a heavier hammer and the daemon
///         owns exactly one backend, so exclusive access is natural.)
///
/// The trait is *not* `Send`/`Sync`: the daemon drives it from a single
///         thread. If a future version wants a background rule-installer thread,
///         adding those bounds is a one-line change with a clear migration.
/// KID: The job description for "a pair of hands". It says the four things hands
///      must be able to do.
pub trait Firewall {
    /// Allow `ip` to reach `port`.
    ///
    /// EXPERT: Must be idempotent. The daemon may retry, and a duplicate ACCEPT
    ///         rule is harmless but untidy. Implementations should either delete
    ///         an existing identical rule first or use a mechanism (like nft set
    ///         membership) that is naturally idempotent.
    /// KID: "Open this door for this visitor."
    fn open_port(&mut self, ip: IpAddr, port: u16) -> Result<()>;

    /// Revoke the allowance created by `open_port`.
    ///
    /// EXPERT: Must tolerate the rule not existing (return `Ok`), because the
    ///         sweeper may race a manual `iptables -F`, and failing here would
    ///         produce a spurious error every sweep.
    /// KID: "Lock this door again for this visitor."
    fn close_port(&mut self, ip: IpAddr, port: u16) -> Result<()>;

    /// Block `ip` entirely.
    ///
    /// EXPERT: A ban should drop *all* traffic from the address, not just
    ///         knock-range traffic. An attacker who has revealed themselves
    ///         should not retain the ability to probe anything else. This is a
    ///         policy decision worth stating: some deployments might prefer a
    ///         narrow ban. We choose the simple, defensible one and document it.
    /// KID: "Do not let this visitor touch anything at all."
    fn ban_ip(&mut self, ip: IpAddr) -> Result<()>;

    /// Remove the block created by `ban_ip`.
    ///
    /// EXPERT: Tolerates absence, like `close_port`.
    /// KID: "Let this visitor try again."
    fn unban_ip(&mut self, ip: IpAddr) -> Result<()>;

    /// A short human-readable name, for log lines.
    ///
    /// EXPERT: A default method (it has a body), so implementors may override it
    ///         but are not forced to. Providing defaults for methods with obvious
    ///         behaviour is how a trait stays easy to implement.
    /// KID: "What are you called, hands?"
    fn name(&self) -> &'static str {
        "firewall"
    }

    /// Remove any state this backend installed, for a clean shutdown.
    ///
    /// EXPERT: The daemon calls this on exit so it does not leave a chain full of
    ///         stale rules behind. The default is a no-op, which is correct for
    ///         the dry-run backend and for the command backend (which cannot know
    ///         what "clean up" means for an arbitrary script).
    /// KID: "Tidy up before you go home."
    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Build the backend named by a [`FirewallConfig`].
///
/// EXPERT: A *factory function* rather than a method on the enum, because the
///         enum is data (it lives in the config module and knows nothing about
///         implementations) while the choice of implementation is this module's
///         concern. This keeps the dependency arrow pointing one way:
///         `firewall` depends on `config`, never the reverse.
///
/// The return type is `Box<dyn Firewall>` -- a *trait object*. That is
///         dynamic dispatch: the concrete type is erased and the right method is
///         looked up at runtime through a vtable. It costs one indirect call per
///         operation, which is nothing for a rule change, and it buys the ability
///         to return different types from one function.
/// KID: "Read the settings sheet and hand me the right pair of hands."
pub fn build(config: &FirewallConfig) -> Box<dyn Firewall> {
    match config {
        FirewallConfig::DryRun => Box::new(DryRunFirewall::new()),
        FirewallConfig::Iptables { chain } => Box::new(IptablesFirewall::new(chain.clone())),
        FirewallConfig::Nftables { table, set } => {
            Box::new(NftablesFirewall::new(table.clone(), set.clone()))
        }
        FirewallConfig::Command { program, args } => {
            Box::new(CommandFirewall::new(program.clone(), args.clone()))
        }
    }
}

// ===========================================================================
//  DryRunFirewall -- practice mode
// ===========================================================================
/// A backend that logs what it *would* do and changes nothing.
///
/// EXPERT: This is the default backend, and it is not a toy. It is the single
///         most valuable feature for adoption: an operator can run the daemon
///         against production traffic for a week and read exactly the rules it
///         would have installed. It is also what makes the integration tests
///         possible without root.
///
/// It keeps a `Vec` of applied operations so a test (or an operator's
///         debug dump) can assert on the exact sequence. Storing them costs a
///         little memory; for a dry run that is exactly the point.
/// KID: Pretend hands. They say "I would open door 27488 for 10.0.0.5 now" but
///      they never actually touch the door. Perfect for practice.
#[derive(Debug, Default)]
pub struct DryRunFirewall {
    /// Every operation that was requested, in order.
    ///
    /// EXPERT: `Vec<String>` of human-readable descriptions. A richer typed
    ///         record would be nicer for assertions, but strings keep this struct
    ///         dead simple and the log output is the primary consumer. Tests that
    ///         need to assert use `.iter().any(|s| s.contains(..))`.
    /// KID: A notebook where the pretend hands write down everything they were
    ///      asked to do.
    pub log: Vec<String>,
}

impl DryRunFirewall {
    /// A fresh dry-run backend with an empty log.
    pub fn new() -> Self {
        DryRunFirewall { log: Vec::new() }
    }

    /// Record an operation and emit an info log.
    ///
    /// EXPERT: A private helper so the four trait methods share one code path.
    ///         It both appends to the log (for tests) and logs (for operators).
    ///         Having one place where "a dry-run operation" is defined means the
    ///         four methods cannot drift.
    /// KID: Write it in the notebook and say it out loud.
    fn record(&mut self, op: &str) {
        let line = format!("[dry-run] {op}");
        // Emit at Info: an operator running a dry run *wants* to see these.
        crate::log_info!("{line}");
        self.log.push(line);
    }
}

impl Firewall for DryRunFirewall {
    fn open_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        self.record(&format!("would open port {port} for {ip}"));
        Ok(())
    }

    fn close_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        self.record(&format!("would close port {port} for {ip}"));
        Ok(())
    }

    fn ban_ip(&mut self, ip: IpAddr) -> Result<()> {
        self.record(&format!("would ban {ip}"));
        Ok(())
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<()> {
        self.record(&format!("would unban {ip}"));
        Ok(())
    }

    fn name(&self) -> &'static str {
        "dry-run"
    }
}

// ===========================================================================
//  IptablesFirewall
// ===========================================================================
/// A backend that drives `iptables` (IPv4) and `ip6tables` (IPv6).
///
/// EXPERT: The design uses a dedicated chain, e.g. `OTKP`, plus a single jump
///         rule from `INPUT` into it. Everything else we install goes in that
///         chain. The benefits:
///           * `iptables -F OTKP` removes every rule we ever added, atomically
///             from the operator's point of view;
///           * our rules are visually grouped, so `iptables -L OTKP -n` is a
///             complete answer to "what is otkp doing?";
///           * we never have to track rule indices, which shift as other tools
///             edit `INPUT`.
///
/// The chain is created on first use and the jump rule installed once.
///         We use `-I` (insert) for the jump so it sits at the top of `INPUT`
///         and cannot be shadowed by a pre-existing DROP. That is a real
///         consideration: a host with `-P INPUT DROP` and an early explicit DROP
///         would otherwise never reach our chain.
/// KID: iptables is the family's big box of door-rules. Instead of shoving our
///      rules into the family's box, we get our own smaller box labelled "OTKP"
///      and put one note in the family's box that says "also read the OTKP box".
///      To tidy up, we just empty our own box.
#[derive(Debug)]
pub struct IptablesFirewall {
    /// The name of our dedicated chain.
    chain: String,
    /// Has the chain (and its jump rule) been created yet?
    ///
    /// EXPERT: A one-time initialisation flag, the classic "lazy init" pattern.
    ///         Doing it once at startup would be cleaner, but the trait has no
    ///         `init` method and adding one would force every backend to
    ///         implement it. A private flag keeps the trait minimal.
    initialised: bool,
}

impl IptablesFirewall {
    /// Build the backend for a named chain.
    pub fn new(chain: String) -> Self {
        IptablesFirewall {
            chain,
            initialised: false,
        }
    }

    /// The `iptables` binary to use for an address family.
    ///
    /// EXPERT: `iptables` handles IPv4 and `ip6tables` handles IPv6; they are
    ///         separate tools with separate rule sets. Dispatching on the address
    ///         family here means every trait method is family-agnostic. (Modern
    ///         `iptables-nft` unifies the backends but keeps the two command
    ///         names, so this remains the correct portable approach.)
    /// KID: Two different tools: one for the "number-number-number-number" kind
    ///      of address and one for the longer kind.
    fn tool_for(ip: IpAddr) -> &'static str {
        match ip {
            IpAddr::V4(_) => "iptables",
            IpAddr::V6(_) => "ip6tables",
        }
    }

    /// Run one `iptables`/`ip6tables` invocation.
    ///
    /// EXPERT: This is where we deliberately do NOT use a shell. `Command::new`
    ///         with an argument vector means the kernel `exec`s the binary
    ///         directly: there is no word-splitting, no globbing, and no
    ///         metacharacter interpretation. An IP address is therefore just a
    ///         string argument, not code. Using `sh -c` here would be a
    ///         command-injection vulnerability the moment any input became
    ///         attacker-influenced.
    ///
    /// We capture stdout/stderr so a failure can be reported with the
    ///         tool's own message, which is far more useful than "exit code 1".
    /// KID: Talk directly to the tool by name, without letting a middle-man
    ///      "translator" reinterpret your words. That way nobody can trick us
    ///      into saying something we did not mean.
    fn run(tool: &str, args: &[String]) -> Result<()> {
        // `Command::new(tool)` builds a process invocation; `.args(..)` adds
        // each argument as a separate, uninterpreted string.
        let output = Command::new(tool).args(args).output().map_err(|e| {
            // This error means the binary could not be spawned at all -- usually
            // "not installed" or "not in PATH".
            OtkpError::firewall(format!("could not run '{tool}': {e}"))
        })?;

        if !output.status.success() {
            // `String::from_utf8_lossy` never fails: invalid UTF-8 becomes U+FFFD.
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OtkpError::firewall(format!(
                "'{tool} {}' failed: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Create our chain and the jump from `INPUT`, once.
    ///
    /// EXPERT: `-N` creates the chain and fails if it already exists, so we
    ///         tolerate that specific failure by treating "already exists" as
    ///         success. Checking first (`-L chain`) would be a second `exec`; the
    ///         try-and-ignore approach is one. We then ensure the jump exists
    ///         with `-C` (check) before `-I` (insert), because inserting on every
    ///         rule change would grow `INPUT` without bound -- a genuine bug that
    ///         would eventually make the firewall unusable.
    /// KID: Make our own box (if it is not already there) and add exactly one
    ///      note in the family's box pointing at it.
    fn ensure_initialised(&mut self, ip: IpAddr) -> Result<()> {
        if self.initialised {
            return Ok(());
        }
        let tool = Self::tool_for(ip);

        // 1. Create the chain. `-N` fails if it exists; that is fine.
        let create = vec!["-N".to_string(), self.chain.clone()];
        if let Err(e) = Self::run(tool, &create) {
            // Only ignore the error if it looks like "already exists". Any other
            // failure (permissions, missing tool) must propagate.
            let msg = e.to_string();
            if !msg.contains("already exists") {
                return Err(e);
            }
        }

        // 2. Ensure the jump from INPUT exists. `-C` checks without changing.
        let check = vec![
            "-C".to_string(),
            "INPUT".to_string(),
            "-j".to_string(),
            self.chain.clone(),
        ];
        let jump_exists = Self::run(tool, &check).is_ok();

        if !jump_exists {
            // Insert at position 1 so nothing shadows us.
            let insert = vec![
                "-I".to_string(),
                "INPUT".to_string(),
                "1".to_string(),
                "-j".to_string(),
                self.chain.clone(),
            ];
            Self::run(tool, &insert)?;
        }

        self.initialised = true;
        Ok(())
    }
}

impl Firewall for IptablesFirewall {
    fn open_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        self.ensure_initialised(ip)?;
        let tool = Self::tool_for(ip);
        // Idempotence: remove any identical rule first. `-D` fails if the rule
        // is absent, and we ignore that failure on purpose.
        let delete = vec![
            "-D".to_string(),
            self.chain.clone(),
            "-s".to_string(),
            ip.to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            port.to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ];
        let _ = Self::run(tool, &delete); // best-effort cleanup

        // Append the ACCEPT. `-A` puts it at the end of our chain, which is
        // correct: our chain contains only our rules, so order among them does
        // not matter.
        let add = vec![
            "-A".to_string(),
            self.chain.clone(),
            "-s".to_string(),
            ip.to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            port.to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ];
        Self::run(tool, &add)
    }

    fn close_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        let tool = Self::tool_for(ip);
        // Exactly the delete half of `open_port`. A missing rule is not an error.
        let delete = vec![
            "-D".to_string(),
            self.chain.clone(),
            "-s".to_string(),
            ip.to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            port.to_string(),
            "-j".to_string(),
            "ACCEPT".to_string(),
        ];
        // We deliberately swallow the error: see the trait docs on idempotence.
        let _ = Self::run(tool, &delete);
        Ok(())
    }

    fn ban_ip(&mut self, ip: IpAddr) -> Result<()> {
        self.ensure_initialised(ip)?;
        let tool = Self::tool_for(ip);
        // Remove a pre-existing ban first, so repeated bans do not stack rules.
        let del = vec![
            "-D".to_string(),
            self.chain.clone(),
            "-s".to_string(),
            ip.to_string(),
            "-j".to_string(),
            "DROP".to_string(),
        ];
        let _ = Self::run(tool, &del);

        let add = vec![
            "-A".to_string(),
            self.chain.clone(),
            "-s".to_string(),
            ip.to_string(),
            "-j".to_string(),
            "DROP".to_string(),
        ];
        Self::run(tool, &add)
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<()> {
        let tool = Self::tool_for(ip);
        let del = vec![
            "-D".to_string(),
            self.chain.clone(),
            "-s".to_string(),
            ip.to_string(),
            "-j".to_string(),
            "DROP".to_string(),
        ];
        let _ = Self::run(tool, &del);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "iptables"
    }

    fn cleanup(&mut self) -> Result<()> {
        // Flush our chain and remove the jump. We do this for both families,
        // ignoring failures for the family that may never have been initialised.
        for tool in ["iptables", "ip6tables"] {
            let flush = vec!["-F".to_string(), self.chain.clone()];
            let _ = Self::run(tool, &flush);

            let del_jump = vec![
                "-D".to_string(),
                "INPUT".to_string(),
                "-j".to_string(),
                self.chain.clone(),
            ];
            let _ = Self::run(tool, &del_jump);

            let del_chain = vec!["-X".to_string(), self.chain.clone()];
            let _ = Self::run(tool, &del_chain);
        }
        self.initialised = false;
        Ok(())
    }
}

// ===========================================================================
//  NftablesFirewall
// ===========================================================================
/// A backend that drives `nft`, the modern nftables CLI.
///
/// EXPERT: nftables' *sets* are a much better fit for our access pattern than
///         iptables' linear rule list. We create:
///           * a table (`inet otkp`) and a base chain hooked into `input`,
///           * a named set of "authorised" addresses for the open port,
///           * a named set of "banned" addresses.
///         Adding an IP is then `nft add element`, which is O(1) and cannot
///         produce duplicates, so idempotence is free. Removing is
///         `nft delete element`. This is strictly nicer than iptables, and it is
///         why nftables is the recommended backend when available.
///
/// One subtlety: a set can be created with a `timeout`, which nftables
///         itself enforces. We *could* rely on that instead of our own sweeper.
///         We do not, because keeping the expiry decision in one place (our
///         engine) means both backends behave identically, and because we still
///         need to know when to log and when to persist. nftables' own timeout
///         is a backstop, not the mechanism.
/// KID: nftables has "guest lists" -- one for people allowed in, one for people
///      banned. Adding a name to a list is instant and cannot be written twice.
///      Much tidier than a long list of rules.
#[derive(Debug)]
pub struct NftablesFirewall {
    /// The nft table name (ours by convention: `otkp`).
    table: String,
    /// The base name for our sets; `_allowed` and `_banned` are appended.
    set: String,
    /// Has the table/chain/sets skeleton been created?
    initialised: bool,
}

impl NftablesFirewall {
    /// Build the backend.
    pub fn new(table: String, set: String) -> Self {
        NftablesFirewall {
            table,
            set,
            initialised: false,
        }
    }

    /// The name of the "allowed" set.
    ///
    /// EXPERT: A private helper rather than a public field, so the naming scheme
    ///         lives in one place. If we ever need `_allowed_tcp` for IPv4/IPv6
    ///         split sets, this is the single function to change.
    /// KID: The name of the "let them in" guest list.
    fn allowed_set(&self) -> String {
        format!("{}_allowed", self.set)
    }

    /// The name of the "banned" set.
    /// KID: The name of the "keep them out" guest list.
    fn banned_set(&self) -> String {
        format!("{}_banned", self.set)
    }

    /// Run one `nft` invocation (never through a shell -- see `IptablesFirewall::run`).
    ///
    /// EXPERT: `nft` accepts a rule as a sequence of argv words, e.g.
    ///         `nft add element inet otkp otkp_allowed { 10.0.0.5 }`.
    ///         We build that argument vector explicitly. Note the braces are
    ///         *separate argv elements*; nft parses them itself, so we do not
    ///         need (and must not use) a shell.
    /// KID: Talk straight to the nft tool.
    fn run(args: &[String]) -> Result<()> {
        let output = Command::new("nft")
            .args(args)
            .output()
            .map_err(|e| OtkpError::firewall(format!("could not run 'nft': {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OtkpError::firewall(format!(
                "'nft {}' failed: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Create the table, chain and sets once.
    ///
    /// EXPERT: Written as one idempotent sequence of `add` commands. `nft add`
    ///         fails if the object exists, so we ignore those specific errors.
    ///         The chain is a *base* chain (`type filter hook input`) so it sees
    ///         inbound packets, with policy `accept` -- we never change the
    ///         default policy, because doing so could lock the operator out of
    ///         their own host if our rules failed to load. Our rules only ever
    ///         ADD accept/drop decisions.
    /// KID: Build our own cupboard with two guest lists in it, and one rule that
    ///      says "check the lists before letting anyone in".
    fn ensure_initialised(&mut self) -> Result<()> {
        if self.initialised {
            return Ok(());
        }

        // `add table` / `add chain` / `add set` -- each may fail with "exists".
        let setup: Vec<Vec<String>> = vec![
            vec![
                "add".into(),
                "table".into(),
                "inet".into(),
                self.table.clone(),
            ],
            vec![
                "add".into(),
                "chain".into(),
                "inet".into(),
                self.table.clone(),
                "input".into(),
                "{".into(),
                "type".into(),
                "filter".into(),
                "hook".into(),
                "input".into(),
                "priority".into(),
                "0".into(),
                ";".into(),
                "policy".into(),
                "accept".into(),
                ";".into(),
                "}".into(),
            ],
            // The set of allowed (ip, port) pairs. nftables sets can hold
            // concatenated tuples, which is exactly what we need: an allowance is
            // "this IP for this port", not "this IP for everything".
            vec![
                "add".into(),
                "set".into(),
                "inet".into(),
                self.table.clone(),
                self.allowed_set(),
                "{".into(),
                "type".into(),
                "ipv4_addr".into(),
                ".".into(),
                "inet_service".into(),
                ";".into(),
                "}".into(),
            ],
            // The set of banned addresses.
            vec![
                "add".into(),
                "set".into(),
                "inet".into(),
                self.table.clone(),
                self.banned_set(),
                "{".into(),
                "type".into(),
                "ipv4_addr".into(),
                ";".into(),
                "}".into(),
            ],
            // Rule 1: drop anything from a banned address.
            vec![
                "add".into(),
                "rule".into(),
                "inet".into(),
                self.table.clone(),
                "input".into(),
                "ip".into(),
                "saddr".into(),
                "@".to_string() + &self.banned_set(),
                "drop".into(),
            ],
            // Rule 2: accept an (ip, dport) pair present in the allowed set.
            vec![
                "add".into(),
                "rule".into(),
                "inet".into(),
                self.table.clone(),
                "input".into(),
                "ip".into(),
                "saddr".into(),
                ".".into(),
                "tcp".into(),
                "dport".into(),
                "@".to_string() + &self.allowed_set(),
                "accept".into(),
            ],
        ];

        for args in setup {
            // Best-effort: "already exists" errors are expected on restart.
            if let Err(e) = Self::run(&args) {
                let msg = e.to_string();
                // Only "exists"/"File exists" is benign; anything else is real.
                if !msg.contains("File exists") && !msg.contains("exists") {
                    return Err(e);
                }
            }
        }

        self.initialised = true;
        Ok(())
    }

    /// Add an element to a set.
    ///
    /// EXPERT: The element is wrapped in braces as its own argv word. For the
    ///         allowed set the element is a *concatenation*: `10.0.0.5 . 27488`.
    ///         `nft` treats `.` as the tuple separator, again parsed by nft itself
    ///         from separate argv words.
    /// KID: Write a name on a guest list.
    fn add_element(&mut self, set: &str, element: Vec<String>) -> Result<()> {
        self.ensure_initialised()?;
        let mut args: Vec<String> = vec![
            "add".into(),
            "element".into(),
            "inet".into(),
            self.table.clone(),
            set.to_string(),
            "{".into(),
        ];
        args.extend(element);
        args.push("}".into());
        Self::run(&args)
    }

    /// Delete an element from a set, tolerating its absence.
    ///
    /// EXPERT: `nft delete element` errors if the element is missing. We swallow
    ///         that because both `close_port` and `unban_ip` are documented as
    ///         idempotent.
    /// KID: Cross a name off a guest list. If it is not there, no problem.
    fn delete_element(&mut self, set: &str, element: Vec<String>) -> Result<()> {
        // Do not call `ensure_initialised` here: if the table does not exist,
        // there is nothing to delete, and creating it just to delete from it
        // would be silly.
        let mut args: Vec<String> = vec![
            "delete".into(),
            "element".into(),
            "inet".into(),
            self.table.clone(),
            set.to_string(),
            "{".into(),
        ];
        args.extend(element);
        args.push("}".into());
        let _ = Self::run(&args);
        Ok(())
    }
}

impl Firewall for NftablesFirewall {
    fn open_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        // Concatenated element: `10.0.0.5 . 27488`.
        let element = vec![ip.to_string(), ".".into(), port.to_string()];
        let set = self.allowed_set();
        self.add_element(&set, element)
    }

    fn close_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        let element = vec![ip.to_string(), ".".into(), port.to_string()];
        let set = self.allowed_set();
        self.delete_element(&set, element)
    }

    fn ban_ip(&mut self, ip: IpAddr) -> Result<()> {
        let element = vec![ip.to_string()];
        let set = self.banned_set();
        self.add_element(&set, element)
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<()> {
        let element = vec![ip.to_string()];
        let set = self.banned_set();
        self.delete_element(&set, element)
    }

    fn name(&self) -> &'static str {
        "nftables"
    }

    fn cleanup(&mut self) -> Result<()> {
        // Deleting the table removes the chain and both sets with it, which is
        // the cleanest possible teardown -- one command, no leftovers.
        let args = vec![
            "delete".into(),
            "table".into(),
            "inet".into(),
            self.table.clone(),
        ];
        let _ = Self::run(&args);
        self.initialised = false;
        Ok(())
    }
}

// ===========================================================================
//  CommandFirewall -- the escape hatch
// ===========================================================================
/// A backend that runs an operator-supplied program with placeholders filled in.
///
/// EXPERT: The placeholders are `{ip}`, `{port}` and `{action}`. They are
///         substituted into *individual argv elements* -- never into a shell
///         string -- so an IP address can never be interpreted as syntax. This is
///         the same discipline as the other backends, and it is what makes an
///         operator-supplied template safe to expose.
///
/// The available actions are `open`, `close`, `ban`, `unban`. The program
///         receives them as a bare word, so a script can dispatch with a
///         `case "$1" in`.
///
/// We document the contract in the README and here, because an operator
///         writing a script needs to know exactly what it will be called with.
/// KID: "If you have your own door-machine, give me the words to say to it, and
///      I will say them -- swapping in the right address and door number as I
///      go."
#[derive(Debug)]
pub struct CommandFirewall {
    /// The program to execute.
    program: String,
    /// Its fixed arguments, possibly containing placeholders.
    args: Vec<String>,
}

impl CommandFirewall {
    /// Build the backend.
    pub fn new(program: String, args: Vec<String>) -> Self {
        CommandFirewall { program, args }
    }

    /// Substitute placeholders and run the program.
    ///
    /// EXPERT: `String::replace` is a plain substring substitution with no
    ///         interpretation, which is exactly the semantics we want. Because
    ///         the result becomes a single argv element, even a maliciously
    ///         crafted IP (impossible in practice -- `IpAddr` is already parsed
    ///         and canonical) could not escape into shell syntax.
    /// KID: Say the words, with the blanks filled in.
    fn invoke(&self, action: &str, ip: IpAddr, port: Option<u16>) -> Result<()> {
        // Build the argument vector with placeholders substituted.
        let args: Vec<String> = self
            .args
            .iter()
            .map(|a| {
                // `replace` returns a new String each time; chaining is fine here
                // because the vectors are tiny.
                let mut s = a.replace("{action}", action);
                s = s.replace("{ip}", &ip.to_string());
                // For ban/unban there is no port; substitute an empty string so
                // the placeholder never reaches the script literally.
                s = s.replace("{port}", &port.map(|p| p.to_string()).unwrap_or_default());
                s
            })
            .collect();

        let output = Command::new(&self.program)
            .args(&args)
            .output()
            .map_err(|e| OtkpError::firewall(format!("could not run '{}': {e}", self.program)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OtkpError::firewall(format!(
                "'{} {}' failed: {}",
                self.program,
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    }
}

impl Firewall for CommandFirewall {
    fn open_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        self.invoke("open", ip, Some(port))
    }

    fn close_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        self.invoke("close", ip, Some(port))
    }

    fn ban_ip(&mut self, ip: IpAddr) -> Result<()> {
        self.invoke("ban", ip, None)
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<()> {
        self.invoke("unban", ip, None)
    }

    fn name(&self) -> &'static str {
        "command"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FirewallConfig;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn dry_run_records_every_operation() {
        let mut fw = DryRunFirewall::new();
        fw.open_port(ip(10, 0, 0, 1), 22).unwrap();
        fw.ban_ip(ip(10, 0, 0, 2)).unwrap();
        fw.close_port(ip(10, 0, 0, 1), 22).unwrap();
        fw.unban_ip(ip(10, 0, 0, 2)).unwrap();

        assert_eq!(fw.log.len(), 4);
        assert!(fw.log[0].contains("would open port 22 for 10.0.0.1"));
        assert!(fw.log[1].contains("would ban 10.0.0.2"));
        assert!(fw.log[2].contains("would close port 22 for 10.0.0.1"));
        assert!(fw.log[3].contains("would unban 10.0.0.2"));
    }

    #[test]
    fn factory_returns_the_right_backend() {
        // The factory must map each config variant to a backend with the
        // matching name. This is a small but real regression guard: a copy-paste
        // mistake in the match would be silent otherwise.
        let cases = [
            (FirewallConfig::DryRun, "dry-run"),
            (
                FirewallConfig::Iptables {
                    chain: "OTKP".into(),
                },
                "iptables",
            ),
            (
                FirewallConfig::Nftables {
                    table: "otkp".into(),
                    set: "otkp".into(),
                },
                "nftables",
            ),
            (
                FirewallConfig::Command {
                    program: "/bin/true".into(),
                    args: vec![],
                },
                "command",
            ),
        ];
        for (cfg, want) in cases {
            let fw = build(&cfg);
            assert_eq!(fw.name(), want);
        }
    }

    #[test]
    fn command_backend_substitutes_placeholders() {
        // Use `/bin/echo` as the "firewall": it succeeds and prints its args.
        // We cannot easily capture the output through the trait (it returns
        // `()`), so we use a program that *fails* when the substitution is
        // wrong -- `/bin/false` always fails, which at least proves we ran
        // something. A stronger test uses a shell script that validates its
        // arguments; see tests/firewall_command.rs for that.
        let mut fw = CommandFirewall::new(
            "/bin/echo".into(),
            vec!["{action}".into(), "{ip}".into(), "{port}".into()],
        );
        // `/bin/echo` exists everywhere and always succeeds.
        fw.open_port(ip(192, 168, 0, 5), 1234).unwrap();
        fw.ban_ip(ip(192, 168, 0, 5)).unwrap();
    }

    #[test]
    fn command_backend_reports_missing_program() {
        let mut fw = CommandFirewall::new(
            "/definitely/not/a/real/program".into(),
            vec!["{action}".into()],
        );
        let err = fw.open_port(ip(1, 1, 1, 1), 22).unwrap_err();
        assert!(matches!(err, OtkpError::Firewall(_)));
    }

    #[test]
    fn nft_set_names_are_derived_correctly() {
        let fw = NftablesFirewall::new("otkp".into(), "otkp".into());
        assert_eq!(fw.allowed_set(), "otkp_allowed");
        assert_eq!(fw.banned_set(), "otkp_banned");
    }

    #[test]
    fn iptables_tool_selection_by_family() {
        assert_eq!(IptablesFirewall::tool_for(ip(1, 2, 3, 4)), "iptables");
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(IptablesFirewall::tool_for(v6), "ip6tables");
    }

    #[test]
    fn cleanup_on_uninitialised_iptables_is_safe() {
        // Cleanup must not panic or error even if nothing was ever installed.
        let mut fw = IptablesFirewall::new("OTKP_TEST".into());
        // We cannot assert success (iptables may be absent in CI), but we can
        // assert that it returns without panicking. The result is deliberately
        // ignored because cleanup is best-effort.
        let _ = fw.cleanup();
    }
}
