//! kanbot backend binary. All logic lives in the library crate.
#![forbid(unsafe_code)]

use kanbot_backend::{cli::Command, config::Config, error::StartupError, telemetry::Telemetry};

fn main() -> Result<(), StartupError> {
    // Before the runtime: the OTLP exporters use blocking HTTP clients.
    let telemetry = Telemetry::init()?;
    let result = run();
    if let Err(error) = &result {
        tracing::error!(?error, "exiting with an error");
    }
    // After the runtime has stopped, so buffered telemetry is flushed.
    telemetry.shutdown();
    result
}

fn run() -> Result<(), StartupError> {
    let command = Command::parse(std::env::args().skip(1))?;
    let config = Config::from_env()?;

    // Built by hand instead of #[tokio::main] so no macro-generated
    // `.expect()` sits in our code.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(StartupError::Runtime)?;
    match command {
        Command::Serve => runtime.block_on(kanbot_backend::run(config)),
        Command::Migrate => runtime.block_on(kanbot_backend::migrate(config)),
    }
}
