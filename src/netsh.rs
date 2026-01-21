use std::{io, process};

fn exec_netsh(args: &[&str]) -> io::Result<()> {
    process::Command::new("netsh")
        .args(args)
        .stderr(process::Stdio::null())
        .stdout(process::Stdio::null())
        .status()
        .and_then(|res| {
            if res.success() {
                Ok(())
            } else {
                Err(io::Error::other("Failed to execute netsh"))
            }
        })
}

pub fn set_interface_name(name: &str, newname: &str) -> io::Result<()> {
    exec_netsh(&["int", "set", "int", "name=", name, "newname=", newname])
}
