#[cfg(unix)]
use users::switch::{set_both_gid, set_both_uid};
#[cfg(unix)]
use users::{get_group_by_name, get_user_by_name};

use std::io::{Error as IOError, ErrorKind};

#[cfg(unix)]
pub fn switch_user(user: &str) -> std::io::Result<()> {
    match get_user_by_name(user) {
        Some(user) => {
            let id = user.uid();
            set_both_uid(id, id)?;
            Ok(())
        }
        None => Err(IOError::new(ErrorKind::NotFound, "User not found")),
    }
}
#[cfg(unix)]
pub fn switch_group(group: &str) -> std::io::Result<()> {
    match get_group_by_name(group) {
        Some(group) => {
            let id = group.gid();
            set_both_gid(id, id)?;
            Ok(())
        }
        None => Err(IOError::new(ErrorKind::NotFound, "Group not found")),
    }
}
#[cfg(windows)]
pub fn switch_user(user: &String) -> std::io::Result<()> {
    //TODO
    Err(IOError::new(ErrorKind::NotFound, "User not found"))
}
#[cfg(windows)]
pub fn switch_group(group: &String) -> std::io::Result<()> {
    //TODO
    Err(IOError::new(ErrorKind::NotFound, "Group not found"))
}
