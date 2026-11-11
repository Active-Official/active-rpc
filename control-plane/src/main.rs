use active_control_plane::mcp;
use active_control_plane::server;

const HELP: &str = "active-control-plane: a demo control plane for Active RPC

usage: active-control-plane [--port PORT] [--read-only] [--mcp [--attach URL]]

  --port PORT     HTTP port to listen on (1..=65535; default 8787, or $PORT)
  --read-only     Serve read-only (same as ACP_READ_ONLY=1)
  --mcp           Run the MCP server on stdin/stdout instead of HTTP
  --attach URL    MCP attach base URL (loopback only; default http://127.0.0.1:8787)
  --help, -h      This text.

Environment:
  PORT            HTTP port (same as --port; --port wins)
  ACP_READ_ONLY   1/true/yes to serve read-only, 0/false/no for read-write";

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

/// Parse `ACP_READ_ONLY`: the truthy spellings an operator would write.
///
/// The vocabulary matches the CLI's `flag_bool` (`true`/`1`/`yes`,
/// `false`/`0`/`no` — RPC-51f): no `on`, which nothing in this codebase
/// accepts. Anything else is refused, so a typo cannot silently pick a mode.
fn read_only_env() -> Result<bool, String> {
    match std::env::var("ACP_READ_ONLY") {
        Err(_) => Ok(false),
        Ok(value) => match value.as_str() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            other => Err(format!(
                "ACP_READ_ONLY must be one of 1/true/yes/0/false/no, got {other:?}"
            )),
        },
    }
}

/// Parse the HTTP port: a value outside 1..=65535, or not a number at all,
/// is refused instead of silently defaulting to 8787 (RPC-51e). Port 0 is
/// refused too: it would bind an ephemeral port the operator cannot know.
fn port_value(args: &[String]) -> Result<u16, String> {
    let raw = arg_value(args, "--port").or_else(|| std::env::var("PORT").ok());
    let Some(raw) = raw else {
        return Ok(8787);
    };
    let port: u16 = raw
        .parse()
        .map_err(|_| format!("--port must be a number 1..=65535, got {raw:?}"))?;
    if port == 0 {
        return Err("--port must be 1..=65535, got 0".to_string());
    }
    Ok(port)
}

#[tokio::main]
async fn main() {
    // `std::env::args()` panics on a non-UTF-8 argument (exit 101), unlike
    // the CLI which handles `args_os` (RPC-51h). Refuse it instead.
    let mut args = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(text) => args.push(text),
            Err(_) => {
                eprintln!("error: an argument is not valid UTF-8");
                std::process::exit(2);
            }
        }
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return;
    }
    // Unknown arguments used to be silently ignored (RPC-51h): a typo such
    // as `--prot 9999` left the plane on the default port with no complaint.
    // A valued flag also needs its value, and a second `--port`/`--attach`
    // is refused rather than letting the first win silently.
    let mut seen_valued: Vec<&str> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--read-only" | "--mcp" => index += 1,
            "--port" | "--attach" => {
                if seen_valued.contains(&args[index].as_str()) {
                    eprintln!("error: {} was passed twice; pass it once", args[index]);
                    std::process::exit(2);
                }
                seen_valued.push(args[index].as_str());
                if args.get(index + 1).is_none() {
                    eprintln!("error: {} needs a value", args[index]);
                    std::process::exit(2);
                }
                index += 2;
            }
            other => {
                eprintln!("error: unknown argument {other}\n\n{HELP}");
                std::process::exit(2);
            }
        }
    }
    let read_only = match read_only_env() {
        Ok(flag) => args.iter().any(|arg| arg == "--read-only") || flag,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    if args.iter().any(|arg| arg == "--mcp") {
        if let Err(error) = mcp::run(arg_value(&args, "--attach"), read_only) {
            eprintln!("active-control-plane MCP: {error}");
            std::process::exit(1);
        }
        return;
    }
    let port = match port_value(&args) {
        Ok(port) => port,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = server::serve(port, read_only).await {
        eprintln!("active-control-plane: {error}");
        std::process::exit(1);
    }
}
