use log::LevelFilter;
use log4rs::{
    Handle,
    append::console::{ConsoleAppender,Target},
    config::{Appender, Config, Logger, Root},
    encode::pattern::PatternEncoder,
};

use std::error;

use log4rs::{
    config::{Deserializers, RawConfig},
    init_config
};

#[cfg(unix)]
mod systemd {
    use std::borrow::Cow;
    use libsystemd::logging::Priority;
    use log::Level;

    #[derive(Debug)]
    pub struct JournalAppender;

    impl JournalAppender {
        pub fn new() -> Self {
            JournalAppender {}
        }
    }

    impl log4rs::append::Append for JournalAppender {
        fn append(&self, record: &log::Record) -> Result<(), anyhow::Error> {
            
            let prio = match record.level() {
                Level::Error => Priority::Error,
                Level::Warn  => Priority::Warning,
                Level::Info  => Priority::Info,
                Level::Debug => Priority::Debug,
                Level::Trace => Priority::Debug,
            };
            let mut fields: Vec<(Cow<str>, Cow<str>)> = Vec::with_capacity(5);

            fields.push(("SYSLOG_PID".into(), std::process::id().to_string().into()));

            if let Some(file) = record.file() {
                fields.push(("CODE_FILE".into(), file.into()));
            }
            if let Some(line) = record.line().map(|l| l.to_string()) {
                fields.push(("CODE_LINE".into(), line.into()));
            }
            // Non-standard fields
            fields.push(("TARGET".into(), record.target().into()));
            if let Some(module) = record.module_path() {
                fields.push(("CODE_MODULE".into(), module.into()))
            }

            libsystemd::logging::journal_send(prio,
                &format!("{}", record.args()),
                fields.into_iter())?;
            Ok(())
        }

        fn flush(&self) {}
    }
}

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
    let (mut has_err, mut has_out, mut has_sysd) = (false, false, false);
    for abc in appenders.iter() {
        match abc.name() {
            "stderr" => has_err=true,
            "stdout" => has_out=true,
            "journal" => has_sysd=true,
            _ => {}
        }
    }
    let mut builder = Config::builder().appenders(appenders);
    if !has_err {
        builder = builder.appender(create_console_logger(Target::Stderr));
    }
    if !has_out {
        builder = builder.appender(create_console_logger(Target::Stdout));
    }
    #[cfg(unix)]
    if !has_sysd {
        builder = builder.appender(Appender::builder().build("journal", Box::new(systemd::JournalAppender::new())));
    }

    let config = builder
        .loggers(config.loggers())
        .build(config.root())?;

    Ok(config)
}
fn create_console_logger(target: Target) -> Appender {
    let ca = ConsoleAppender::builder() // "{d} {l} {t} - {m}{n}".
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S %Z)(utc)} {h({l})} {t} - {m}{n}")))
        .target(target).build();
    let name = match target {
        Target::Stdout => "stdout",
        Target::Stderr => "stderr",
    };
    Appender::builder().build(name, Box::new(ca))
}

pub fn init_stderr_logging() -> Handle {
    let root_level = if let Ok(level) = std::env::var("RUST_LOG") {
        match level.as_str() {
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "trace" => LevelFilter::Trace,
            _ => {
            eprintln!("unsupported log level: {}", &level);
            LevelFilter::Warn},
        }
    }else{
        LevelFilter::Warn
    };

    #[cfg(unix)]
    let def_appender = {
        let mut invoked_by_systemd = false;
        if let Ok(level) = std::env::var("SYSTEMD_EXEC_PID") {
            if level == std::process::id().to_string() {
                invoked_by_systemd = true;
            }
        }
        if invoked_by_systemd {
            Appender::builder().build("stderr", Box::new(systemd::JournalAppender::new()))
        }else{
            create_console_logger(Target::Stderr)
        }
    };
    #[cfg(not(unix))]
    let def_appender = create_console_logger(Target::Stderr);

    let config = Config::builder()
        .appender(def_appender)
        .logger(Logger::builder().build("flash_rust_ws", root_level))
        .logger(Logger::builder().build("hyper", root_level))
        .logger(Logger::builder().build("async_fcgi", root_level))
        .build(Root::builder().appender("stderr").build(LevelFilter::Warn))
        .unwrap();

    init_config(config).unwrap()
}