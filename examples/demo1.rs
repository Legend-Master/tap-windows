use std::io::{self, Read};
use tap_windows::{Device, HARDWARE_ID};
use windows::{core::HRESULT, Win32::Foundation::ERROR_GEN_FAILURE};

const MY_INTERFACE: &str = "MyInterface";

fn main() -> std::io::Result<()> {
    let mut dev = Device::open(HARDWARE_ID, MY_INTERFACE);
    if let Err(e) = dev {
        if e.kind() == io::ErrorKind::NotFound {
            println!("Device is not exist, try creating a new one");
            let new_dev = Device::create(HARDWARE_ID)?;
            new_dev.set_name(MY_INTERFACE)?;
            dev = Ok(new_dev);
        } else {
            if e.raw_os_error() == Some(HRESULT::from(ERROR_GEN_FAILURE).0) {
                println!("Device is already in use, exiting...");
            }
            return Err(e);
        }
    }
    let mut dev = dev?;

    dev.up()?;

    // Set the device ip
    dev.set_ip([10, 20, 60, 1], [255, 255, 255, 0])?;

    // Setup read buffer
    let mtu = dev.get_mtu().unwrap_or(1500);

    let mut buf = vec![0; mtu as usize];
    loop {
        let amt = dev.read(&mut buf)?;

        let data = &buf[..amt];
        let len = data.len();
        let header = &data[0..(20.min(len))];
        println!("Read packet size {len} bytes. Header data {header:?}");
    }
}
