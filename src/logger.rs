use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::config::{
    Appender,
    Config,
    Logger,
    Root
};

pub fn main() {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{l} {m}{n}")))
        .build();

    let file_logger = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("[{d}] {l} - {m}{n}")))
        .build("logs/app.log")
        .unwrap();

    let config = Config::builder()
        .appender(Appender::builder()
            .filter(Box::new(ThresholdFilter::new(LevelFilter::Info)))
            .build("stdout", Box::new(stdout)))
        .appender(Appender::builder()
            .build("log-file", Box::new(file_logger)))
        .build(
            Root::builder()
                .appender("stdout")
                .appender("log-file")
                .build(LevelFilter::Trace))
        .unwrap();

    let handle = log4rs::init_config(config).unwrap();

    // use handle to change logger configuration at runtime
}