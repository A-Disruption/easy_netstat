//! Explicit UAC relaunch only; never changes firewall/audit/service settings.
fn launch_error(code: u32) -> String {
    if code == 1223 {
        "Administrator restart cancelled. The current session is still open.".into()
    } else {
        format!(
            "Could not restart as administrator (Windows error {code}). The current session is still open."
        )
    }
}

#[cfg(windows)]
pub fn is_elevated() -> Result<bool, String> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = std::ptr::null_mut();
    // SAFETY: live process pseudo-handle and writable token out-parameter.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    // SAFETY: exact-sized writable TOKEN_ELEVATION; token remains open for call.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    let error = (ok == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseHandle(token);
    }
    if let Some(error) = error {
        return Err(error.to_string());
    }
    if returned != std::mem::size_of::<TOKEN_ELEVATION>() as u32 {
        return Err("Invalid token elevation response".into());
    }
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(windows)]
pub fn restart_as_administrator() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Com::{
            COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
        },
        UI::Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
    };
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let directory = exe.parent().ok_or("Cannot locate application directory")?;
    let exe: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let directory: Vec<u16> = directory.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    // This function runs on a worker, not the UI thread. Balance successful COM
    // initialization, including S_FALSE, on every path.
    let hr = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if hr < 0 {
        return Err(format!(
            "Cannot initialize administrator restart (HRESULT {hr:#x})"
        ));
    }
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }
    let _apartment = Apartment;
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: exe.as_ptr(),
        lpDirectory: directory.as_ptr(),
        // No forwarded arguments, scripts or untrusted working directory.
        nShow: 1,
        ..SHELLEXECUTEINFOW::default()
    };
    // SAFETY: all UTF-16 strings remain alive throughout this synchronous call.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(launch_error(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
        ));
    }
    if info.hProcess.is_null() {
        return Err(
            "Windows did not return a restarted process; the current session remains open.".into(),
        );
    }
    unsafe {
        CloseHandle(info.hProcess);
    }
    Ok(())
}
#[cfg(not(windows))]
pub fn is_elevated() -> Result<bool, String> {
    Err("Windows elevation is unavailable".into())
}
#[cfg(not(windows))]
pub fn restart_as_administrator() -> Result<(), String> {
    Err("Windows elevation is unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_and_failed_restarts_keep_a_clear_recovery_message() {
        assert!(launch_error(1223).contains("cancelled"));
        assert!(launch_error(5).contains("error 5"));
        assert!(launch_error(5).contains("still open"));
    }
    #[test]
    #[cfg(windows)]
    fn current_token_is_readable_without_elevation() {
        assert!(is_elevated().is_ok());
    }
}
