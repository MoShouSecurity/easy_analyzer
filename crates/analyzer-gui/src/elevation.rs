use analyzer_app::AnalysisService;
use anyhow::{Result, bail};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum ElevationResult {
    Launched,
    Cancelled,
    AlreadyElevated,
}

pub fn status() -> (Option<bool>, Option<String>) {
    if !cfg!(windows) {
        return (None, None);
    }
    match AnalysisService::windows_process_is_elevated() {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(format!("权限状态读取失败：{error:#}"))),
    }
}

pub fn request_admin_window() -> Result<ElevationResult> {
    #[cfg(windows)]
    {
        if matches!(AnalysisService::windows_process_is_elevated(), Ok(true)) {
            return Ok(ElevationResult::AlreadyElevated);
        }
        // A fresh thread has no pre-existing COM apartment; UAC never blocks the UI thread.
        std::thread::Builder::new()
            .name("uac-launch".into())
            .spawn(windows_launch)?
            .join()
            .map_err(|_| anyhow::anyhow!("Windows 提权线程意外退出"))?
    }
    #[cfg(not(windows))]
    bail!("UAC 提权仅适用于 Windows")
}

#[cfg(windows)]
fn windows_launch() -> Result<ElevationResult> {
    use std::{mem::size_of, os::windows::ffi::OsStrExt, ptr::null};
    use windows_sys::{
        Win32::{
            Foundation::{ERROR_CANCELLED, GetLastError},
            System::Com::{
                COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
            },
            UI::{
                Shell::{
                    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW,
                },
                WindowsAndMessaging::SW_SHOWNORMAL,
            },
        },
        core::w,
    };
    struct ComApartment;
    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: This thread successfully initialized COM exactly once.
            unsafe { CoUninitialize() };
        }
    }
    // SAFETY: Called on a newly created thread, with no reserved pointer.
    let result = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if result < 0 {
        bail!("无法初始化 Windows 提权接口：HRESULT {result:#x}");
    }
    let _com = ComApartment;
    // The frontend cannot choose an executable, arguments or an elevated working directory.
    let executable = std::env::current_exe()?;
    let file: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let directory: Vec<u16> = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("无法确定程序所在目录"))?
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut launch = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: w!("runas"),
        lpFile: file.as_ptr(),
        lpParameters: w!("--live-processes --temporary"),
        lpDirectory: directory.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    // SAFETY: All NUL-terminated strings and the structure stay alive until the call returns.
    if unsafe { ShellExecuteExW(&mut launch) } == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_CANCELLED {
            return Ok(ElevationResult::Cancelled);
        }
        return Err(std::io::Error::from_raw_os_error(error as i32).into());
    }
    Ok(ElevationResult::Launched)
}
