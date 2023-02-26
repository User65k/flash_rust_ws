use std::fs::File;
use std::io::Write;
use std::process;

use crate::config::Utf8PathBuf;

pub fn create_pid_file(file_path: Utf8PathBuf) -> std::io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(process::id().to_string().as_bytes())?;
    Ok(())
}
