use std::process::ExitCode;

fn main() -> ExitCode {
    let code = polytunnel::run(
        std::env::args_os().skip(1).collect(),
        &polytunnel::Hooks::real(),
    );
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
