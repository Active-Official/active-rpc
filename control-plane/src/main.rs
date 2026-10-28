use active_control_plane::mcp;
use active_control_plane::server;

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let read_only = args.iter().any(|arg| arg == "--read-only")
        || std::env::var("ACP_READ_ONLY").ok().as_deref() == Some("1");
    if args.iter().any(|arg| arg == "--mcp") {
        if let Err(error) = mcp::run(arg_value(&args, "--attach"), read_only) {
            eprintln!("active-control-plane MCP: {error}");
            std::process::exit(1);
        }
        return;
    }
    let port = arg_value(&args, "--port")
        .or_else(|| std::env::var("PORT").ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(8787);
    if let Err(error) = server::serve(port, read_only).await {
        eprintln!("active-control-plane: {error}");
        std::process::exit(1);
    }
}
