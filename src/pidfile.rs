use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process;

pub fn create_pid_file(file_path: PathBuf) -> std::io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(process::id().to_string().as_bytes())?;
    Ok(())
}
