use std::path::Path;

use anyhow::Result;

#[cfg(target_os = "linux")]
pub fn apply(data_dir: &Path, pt: Option<&Path>) -> Result<String> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };
    let abi = ABI::V2;
    let mut read_only: Vec<&Path> = vec![
        Path::new("/dev/urandom"),
        Path::new("/dev/null"),
        Path::new("/etc/ssl"),
        Path::new("/proc/self"),
        Path::new("/sys/devices/system/cpu"),
    ];
    let mut exec: Vec<&Path> = Vec::new();
    if let Some(p) = pt {
        exec.extend([
            p,
            Path::new("/usr/lib"),
            Path::new("/lib"),
            Path::new("/lib64"),
        ]);
        read_only.push(Path::new("/etc/ld.so.cache"));
    }
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules([data_dir], AccessFs::from_all(abi)))?
        .add_rules(path_beneath_rules(read_only, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(
            exec,
            AccessFs::from_read(abi) | AccessFs::Execute,
        ))?
        .restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => "Landlock sandbox: enforced".into(),
        RulesetStatus::PartiallyEnforced => "Landlock sandbox: partial (old kernel)".into(),
        RulesetStatus::NotEnforced => "Landlock sandbox: not supported by this kernel".into(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn apply(_data_dir: &Path, _pt: Option<&Path>) -> Result<String> {
    Ok("sandbox: not available on this system (Linux only)".into())
}
