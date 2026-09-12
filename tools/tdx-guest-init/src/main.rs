//! Native initramfs PID 1 for the no-secrets C3 TDX boot spike.

#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{self, Read},
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        unix::process::CommandExt,
    },
    path::Path,
    ptr,
};

const ROOT_DEVICE: &str = "/dev/dm-0";
const NEW_ROOT: &str = "/newroot";
const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
const BUFFER_BYTES: usize = 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::process::id() != 1 {
        return Err("tdx-guest-init must run as PID 1".into());
    }
    mount_early()?;
    establish_null_stdio()?;
    verify_release_contract()?;
    mount_root()?;
    sweep_verity_root(expected_root_bytes()?)?;
    wait_for_randomness()?;
    mount_tmpfs()?;
    switch_to_verified_root()?;
    exec_agent(&private_ipv4_listener()?)
}

fn release_value(name: &str, value: Option<&'static str>) -> io::Result<&'static str> {
    value.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} was not pinned at compile time"),
        )
    })
}

fn expected_root_bytes() -> io::Result<u64> {
    release_value(
        "ZAINO_EXPECTED_ROOT_BYTES",
        option_env!("ZAINO_EXPECTED_ROOT_BYTES"),
    )?
    .parse()
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid compiled root geometry"))
}

fn verify_release_contract() -> io::Result<()> {
    let cmdline = fs::read("/proc/cmdline")?;
    let expected_cmdline = release_value(
        "ZAINO_EXPECTED_CMDLINE_SHA256",
        option_env!("ZAINO_EXPECTED_CMDLINE_SHA256"),
    )?;
    if hex::encode(Sha256::digest(&cmdline)) != expected_cmdline {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel command line is not the compiled release command line",
        ));
    }
    let expected_uuid = release_value(
        "ZAINO_EXPECTED_DM_UUID",
        option_env!("ZAINO_EXPECTED_DM_UUID"),
    )?;
    if fs::read_to_string("/sys/block/dm-0/dm/uuid")?.trim_end() != expected_uuid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "device-mapper identity mismatch",
        ));
    }
    Ok(())
}

fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))
}

fn mkdir(path: &str, mode: u32) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn require_directory(path: &str) -> io::Result<()> {
    if fs::metadata(path)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "required mountpoint is not a directory",
        ))
    }
}

fn mount(
    source: &str,
    target: &str,
    kind: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = cstring(source)?;
    let target = cstring(target)?;
    let kind = cstring(kind)?;
    let data = data.map(cstring).transpose()?;
    // SAFETY: pointers refer to live NUL-terminated strings for this syscall.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            kind.as_ptr(),
            flags,
            data.as_ref().map_or(ptr::null(), |v| v.as_ptr().cast()),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn move_mount(source: &str, target: &str) -> io::Result<()> {
    let source = cstring(source)?;
    let target = cstring(target)?;
    // SAFETY: both pointers are live NUL-terminated mount paths.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            ptr::null(),
            libc::MS_MOVE,
            ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn mount_early() -> io::Result<()> {
    for path in ["/dev", "/proc", "/sys"] {
        mkdir(path, 0o755)?;
    }
    mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        None,
    )?;
    mount(
        "proc",
        "/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    mount(
        "sysfs",
        "/sys",
        "sysfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    mkdir("/sys/kernel/config", 0o755)?;
    mount(
        "configfs",
        "/sys/kernel/config",
        "configfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
}

fn establish_null_stdio() -> io::Result<()> {
    let null = File::options().read(true).write(true).open("/dev/null")?;
    // The kernel may start the no-console guest with fd 0 closed, allowing the
    // open above to return 0 with O_CLOEXEC. First duplicate it above stdio.
    // SAFETY: fcntl duplicates one live descriptor to a number at least 3.
    let source = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if source < 0 {
        return Err(io::Error::last_os_error());
    }
    // Closing the original before installing stdio prevents a File that was
    // allocated as fd 0, 1, or 2 from later closing the replacement.
    drop(null);
    // SAFETY: source is the newly-created, uniquely owned descriptor.
    let source = unsafe { OwnedFd::from_raw_fd(source) };
    for target in [0, 1, 2] {
        // SAFETY: source is live and targets are standard descriptors.
        if unsafe { libc::dup2(source.as_raw_fd(), target) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn mount_root() -> io::Result<()> {
    mkdir(NEW_ROOT, 0o755)?;
    if !fs::metadata(ROOT_DEVICE)?.file_type().is_block_device() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "verified root is not a block device",
        ));
    }
    mount(
        ROOT_DEVICE,
        NEW_ROOT,
        "ext4",
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )
}

fn sweep_reader(mut reader: impl Read, bytes: u64) -> io::Result<()> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(BUFFER_BYTES as u64))
            .map_err(|_| io::Error::other("root sweep size conversion"))?;
        reader.read_exact(&mut buffer[..count])?;
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "root exceeds fixed geometry",
        ))
    }
}

fn sweep_verity_root(expected: u64) -> io::Result<()> {
    let mut root = File::open(ROOT_DEVICE)?;
    let mut actual = 0_u64;
    // SAFETY: BLKGETSIZE64 writes one u64 to the live output pointer.
    if unsafe { libc::ioctl(root.as_raw_fd(), BLKGETSIZE64, &mut actual) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if actual == 0 || actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "root geometry mismatch",
        ));
    }
    sweep_reader(&mut root, actual)
}

fn wait_for_randomness() -> io::Result<()> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("OS CSPRNG unavailable"))
}

fn mount_tmpfs() -> io::Result<()> {
    for (path, data) in [
        ("/newroot/run", "mode=0755,size=16M"),
        ("/newroot/tmp", "mode=1777,size=64M"),
    ] {
        require_directory(path)?;
        mount(
            "tmpfs",
            path,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(data),
        )?;
    }
    Ok(())
}

fn remove_initramfs_contents() -> io::Result<()> {
    for entry in fs::read_dir("/")? {
        let entry = entry?;
        let name = entry.file_name();
        if ["dev", "proc", "sys", "newroot"]
            .iter()
            .any(|keep| name == *keep)
        {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn switch_to_verified_root() -> io::Result<()> {
    remove_initramfs_contents()?;
    for name in ["dev", "proc", "sys"] {
        let target = format!("{NEW_ROOT}/{name}");
        require_directory(&target)?;
        move_mount(&format!("/{name}"), &target)?;
        fs::remove_dir(format!("/{name}"))?;
    }
    std::env::set_current_dir(NEW_ROOT)?;
    move_mount(".", "/")?;
    let dot = cstring(".")?;
    // SAFETY: dot names the verified root at the current directory.
    if unsafe { libc::chroot(dot.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    std::env::set_current_dir("/")?;
    verify_final_mounts()
}

fn verify_final_mounts() -> io::Result<()> {
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let root = mounts
        .lines()
        .find(|line| line.split(' ').nth(4) == Some("/"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "root mount absent"))?;
    if !root
        .split(' ')
        .nth(5)
        .unwrap_or_default()
        .split(',')
        .any(|option| option == "ro")
        || Path::new(NEW_ROOT).exists()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "final root is mutable or initramfs reachable",
        ));
    }
    let root_device = fs::metadata(ROOT_DEVICE)?.rdev();
    let expected_device = format!("{}:{}", libc::major(root_device), libc::minor(root_device));
    if root.split(' ').nth(2) != Some(expected_device.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "final root is not the authenticated dm device",
        ));
    }
    for path in ["/run", "/tmp"] {
        let line = mounts
            .lines()
            .find(|line| line.split(' ').nth(4) == Some(path))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "runtime tmpfs absent"))?;
        let options = line.split(' ').nth(5).unwrap_or_default();
        if !["noexec", "nodev", "nosuid"]
            .iter()
            .all(|required| options.split(',').any(|actual| actual == *required))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runtime tmpfs flags absent",
            ));
        }
    }
    for (path, required) in [
        ("/dev", ["nosuid", "noexec", ""]),
        ("/proc", ["nosuid", "nodev", "noexec"]),
        ("/sys", ["nosuid", "nodev", "noexec"]),
        ("/sys/kernel/config", ["nosuid", "nodev", "noexec"]),
    ] {
        let line = mounts
            .lines()
            .find(|line| line.split(' ').nth(4) == Some(path))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "kernel mount absent"))?;
        let options = line.split(' ').nth(5).unwrap_or_default();
        if required
            .iter()
            .filter(|flag| !flag.is_empty())
            .any(|flag| !options.split(',').any(|actual| actual == *flag))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel mount flags absent",
            ));
        }
    }
    Ok(())
}

fn private_ipv4_listener() -> io::Result<String> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: getifaddrs initializes head on success.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut current = head;
    let mut selected = None;
    while !current.is_null() {
        // SAFETY: current is a node in the getifaddrs list.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null()
            && unsafe { (*entry.ifa_addr).sa_family as i32 } == libc::AF_INET
        {
            // SAFETY: AF_INET fixes the sockaddr layout.
            let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            if ip.is_private() || ip.is_link_local() {
                selected = Some(format!("{ip}:8443"));
                break;
            }
        }
        current = entry.ifa_next;
    }
    // SAFETY: head came from successful getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    selected.ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "private IPv4 absent"))
}

fn exec_agent(listen: &str) -> Result<(), Box<dyn std::error::Error>> {
    // No subprocess is permitted after replacement. Ignore SIGCHLD so any
    // unexpected inherited child is auto-reaped while the agent is PID 1.
    // SAFETY: SIG_IGN is a valid SIGCHLD disposition.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
    // The initramfs is not an authority channel. Only the fixed stdio set may
    // cross into the final evidence agent.
    // SAFETY: close_range closes the inclusive descriptor range without
    // touching descriptors 0, 1, or 2.
    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let error = std::process::Command::new("/usr/lib/zaino/tdx-evidence-agent")
        .args(["--listen", listen, "--provider-timeout-seconds", "10"])
        .env_clear()
        .exec();
    Err(error.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_sweep_rejects_truncation_and_trailing_data() {
        assert!(sweep_reader(&b"abcd"[..], 4).is_ok());
        assert_eq!(
            sweep_reader(&b"abc"[..], 4).expect_err("truncated").kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            sweep_reader(&b"abcde"[..], 4).expect_err("trailing").kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn null_stdio_survives_closed_initial_descriptors() {
        let mut command = std::process::Command::new(
            std::env::current_exe().expect("test executable path is available"),
        );
        command
            .args([
                "--exact",
                "tests::null_stdio_closed_descriptor_child",
                "--nocapture",
            ])
            .env("ZAINO_CLOSED_STDIO_PROBE", "1");
        let status = command.status().expect("closed-stdio subprocess starts");
        assert!(status.success(), "stdio descriptor probe failed");
    }

    #[test]
    fn null_stdio_closed_descriptor_child() {
        if std::env::var_os("ZAINO_CLOSED_STDIO_PROBE").is_none() {
            return;
        }
        for descriptor in [0, 1, 2] {
            // SAFETY: this isolated child deliberately recreates a no-console
            // PID1 descriptor state immediately before the function under test.
            unsafe { libc::close(descriptor) };
        }
        establish_null_stdio().expect("stdio is installed from devnull");
        for descriptor in [0, 1, 2] {
            // SAFETY: F_GETFD reads flags for a fixed descriptor.
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            assert!(flags >= 0, "stdio descriptor {descriptor} is open");
            assert_eq!(flags & libc::FD_CLOEXEC, 0, "stdio survives exec");
        }
        // Avoid test-harness I/O after the descriptor assertions.
        // SAFETY: the isolated child completed every assertion.
        unsafe { libc::_exit(0) }
    }
}
