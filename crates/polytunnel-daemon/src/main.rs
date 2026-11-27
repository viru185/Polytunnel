use std::process::ExitCode;

fn main() -> ExitCode {
    let code = polytunnel_daemon::run(
        std::env::args_os().skip(1).collect(),
        &polytunnel_daemon::Hooks::real(),
    );
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
