//! `pathguard` command line: scenario demos, the scenario matrix, key generation
//! and policy presets.

use pathguard::sim;
use pathguard::util;
use pathguard::{Identity, Policy};
use std::io::Write;
use std::process::ExitCode;

const HELP: &str = "pathguard: decoy-assisted authenticated transmission (research prototype)

USAGE:
    pathguard <COMMAND> [OPTIONS]

COMMANDS:
    demo [--scenario NAME] [--policy NAME|FILE]   Run one simulated scenario and print the audit trail
    scenarios                                     List built-in scenarios
    matrix                                        Run every scenario under baseline, balanced and paranoid
    policy [baseline|balanced|paranoid]           Print a policy preset as TOML
    keygen <FILE>                                 Create an Ed25519 identity (secret seed written to FILE, mode 0600)
    version                                       Print the version
    help                                          Print this help

This is an unaudited research prototype. Do not use it to protect real secrets.
";

fn load_policy(spec: &str) -> Result<Policy, String> {
    if let Some(p) = Policy::preset(spec) {
        return Ok(p);
    }
    let text = std::fs::read_to_string(spec).map_err(|e| format!("cannot read policy '{spec}': {e}"))?;
    Policy::from_toml_str(&text).map_err(|e| e.to_string())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn cmd_demo(args: &[String]) -> Result<(), String> {
    let name = flag(args, "--scenario").unwrap_or_else(|| "honest".into());
    let policy = load_policy(&flag(args, "--policy").unwrap_or_else(|| "balanced".into()))?;
    let scn = sim::scenarios()
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| format!("unknown scenario '{name}' (see `pathguard scenarios`)"))?;
    println!("scenario: {} ({})", scn.name, scn.description);
    let o = sim::run(&scn, &policy);
    println!("result:   {} (receiver got payload: {}, plaintext visible on path: {})", o.status, o.delivered, o.plaintext_leaked);
    if let Some(r) = &o.report {
        println!("{}", r.render());
    }
    Ok(())
}

fn cmd_matrix() {
    let outcomes = sim::matrix();
    let names = ["baseline", "balanced", "paranoid"];
    println!("{:<24} {:<14} {:<14} {:<14}", "scenario", names[0], names[1], names[2]);
    println!("{}", "-".repeat(68));
    let mut leaked = false;
    for scn in sim::scenarios() {
        let mut cells = Vec::new();
        for n in names {
            let o = outcomes.iter().find(|o| o.scenario == scn.name && o.policy == n).expect("matrix is complete");
            leaked |= o.plaintext_leaked;
            let alerts = o.report.as_ref().map_or(0, |r| r.findings.len());
            let mut c = o.status.to_string();
            if o.attempts > 1 {
                c.push_str(&format!(" x{}", o.attempts));
            }
            if o.status == "delivered" && alerts > 0 {
                c.push('*');
            }
            cells.push(c);
        }
        println!("{:<24} {:<14} {:<14} {:<14}", scn.name, cells[0], cells[1], cells[2]);
    }
    println!();
    println!("xN = succeeded or ended after N attempts (fresh handshake and keys each time)");
    println!("*  = delivered, but findings were recorded (alerts raised)");
    println!("payload plaintext ever visible to an on-path observer: {leaked}");
}

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let file = args.first().ok_or("usage: pathguard keygen <FILE>")?;
    let id = Identity::generate();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(file).map_err(|e| format!("cannot create '{file}': {e}"))?;
    writeln!(f, "{}", util::hex(&id.seed_bytes())).map_err(|e| e.to_string())?;
    let public = id.public();
    println!("public identity: {}", public.to_hex());
    println!("fingerprint:     {}", public.fingerprint());
    println!("secret seed written to {file} (keep it private)");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let result = match cmd {
        "demo" => cmd_demo(rest),
        "scenarios" => {
            for s in sim::scenarios() {
                println!("{:<24} {}", s.name, s.description);
            }
            Ok(())
        }
        "matrix" => {
            cmd_matrix();
            Ok(())
        }
        "policy" => {
            let name = rest.first().map(String::as_str).unwrap_or("balanced");
            match Policy::preset(name) {
                Some(p) => {
                    print!("{}", p.to_toml());
                    Ok(())
                }
                None => Err(format!("unknown preset '{name}'")),
            }
        }
        "keygen" => cmd_keygen(rest),
        "version" | "--version" | "-V" => {
            println!("pathguard {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{HELP}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
