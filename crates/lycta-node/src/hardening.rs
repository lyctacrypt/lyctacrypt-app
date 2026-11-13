#![allow(unsafe_code)]

pub fn apply() -> Vec<String> {
    imp::apply()
}

#[cfg(unix)]
mod imp {
    pub fn apply() -> Vec<String> {
        let mut notes = Vec::new();

        unsafe {
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0 {
                notes.push("core dumps disabled".into());
            }
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
                notes.push("process not dumpable (PR_SET_DUMPABLE=0)".into());
            }
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let unlimited = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) == 0
                && lim.rlim_cur == libc::RLIM_INFINITY;

            if unlimited && libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 {
                notes.push("memory locked in RAM (mlockall)".into());
            } else {
                notes.push("memory NOT locked: use `ulimit -l unlimited` or encrypted swap".into());
            }
        }
        notes
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };

    pub fn apply() -> Vec<String> {
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        }
        vec![
            "Windows error reports (crash dumps) disabled".into(),
            "memory NOT locked on Windows: disable the page file or use BitLocker".into(),
        ]
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub fn apply() -> Vec<String> {
        vec!["no hardening available on this platform".into()]
    }
}
