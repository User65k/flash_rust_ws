use log::LevelFilter;
use log4rs::{
    Handle,
    append::console::{ConsoleAppender,Target},
    config::{Appender, Config, Logger, Root},
    encode::pattern::PatternEncoder,
};

use std::{
    error,
};

use log4rs::{
    config::{Deserializers, RawConfig},
    init_config
};

pub fn init_file(config: RawConfig, handle: &Handle) -> Result<(), Box<dyn error::Error>>
{
    let deserializers = Deserializers::default();
    //let refresh_rate = config.refresh_rate();
    let config = deserialize(&config, &deserializers)?;

    handle.set_config(config);
    Ok(())
}
fn deserialize(config: &RawConfig, deserializers: &Deserializers) ->  Result<Config, Box<dyn error::Error>> {
    let (appenders, errors) = config.appenders_lossy(deserializers);
    if !errors.is_empty() {
        return Err(Box::new(errors));
    }

    let config = Config::builder()
        .appenders(appenders)
        .loggers(config.loggers())
        .build(config.root())?;

    Ok(config)
}

pub fn init_stderr_logging() -> Handle {

    let stderr = ConsoleAppender::builder() // "{d} {l} {t} - {m}{n}".
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S %Z)(utc)} {h({l})} {t} - {m}{n}")))
        .target(Target::Stderr).build();

    let root_level = if let Ok(level) = std::env::var("RUST_LOG") {
        match level.as_str() {
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Warn,
        }
    }else{
        LevelFilter::Warn
    };

    let config = Config::builder()
        .appender(Appender::builder().build("stderr", Box::new(stderr)))
        .logger(Logger::builder().build("flash_rust_ws::config", LevelFilter::Info))
        .logger(Logger::builder().build("flash_rust_ws", root_level))
        .logger(Logger::builder().build("hyper", root_level))
        .logger(Logger::builder().build("async_fcgi", root_level))
        .build(Root::builder().appender("stderr").build(LevelFilter::Warn))
        .unwrap();

    init_config(config).unwrap()
}