use crate::execution::ExecutionContext;
use anyhow::{Context, Result, bail};
use std::{
    mem::size_of,
    ptr::{null, null_mut},
    sync::{Mutex, MutexGuard, TryLockError},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, SetLastError},
    Security::{
        AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, SE_DEBUG_NAME,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
        TOKEN_QUERY, TokenElevation,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct Token(HANDLE);
impl Token {
    fn open(access: u32) -> Result<Self> {
        let mut handle = null_mut();
        // SAFETY: The pseudo process handle is valid and handle is a writable out parameter.
        if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut handle) } == 0 {
            return Err(std::io::Error::last_os_error()).context("无法读取 Windows 进程令牌");
        }
        Ok(Self(handle))
    }
}
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: This object owns the token handle returned by OpenProcessToken.
        unsafe { CloseHandle(self.0) };
    }
}

pub fn is_elevated() -> Result<bool> {
    let token = Token::open(TOKEN_QUERY)?;
    let mut value = TOKEN_ELEVATION::default();
    let mut length = 0;
    // SAFETY: The token is valid, and the buffer size matches the writable token structure.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut value as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("无法确认 Windows 提权状态");
    }
    Ok(value.TokenIsElevated != 0)
}

// The privilege belongs to the process token, including sysinfo worker threads.
// Serialize collectors so one capture cannot restore another capture's privilege.
static CAPTURE_PRIVILEGE: Mutex<()> = Mutex::new(());
pub struct DebugPrivilege {
    token: Token,
    previous: TOKEN_PRIVILEGES,
    restore: bool,
    _lock: MutexGuard<'static, ()>,
}
impl DebugPrivilege {
    pub fn acquire(ctx: &ExecutionContext) -> Result<Self> {
        let lock = loop {
            ctx.check()?;
            match CAPTURE_PRIVILEGE.try_lock() {
                Ok(lock) => break lock,
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(20)),
                Err(TryLockError::Poisoned(_)) => bail!("进程采集权限锁不可用"),
            }
        };
        let token = Token::open(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?;
        let mut guard = Self {
            token,
            previous: TOKEN_PRIVILEGES::default(),
            restore: false,
            _lock: lock,
        };
        let mut requested = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            ..Default::default()
        };
        // SAFETY: SE_DEBUG_NAME is a static NUL-terminated Windows privilege name.
        if unsafe {
            LookupPrivilegeValueW(null(), SE_DEBUG_NAME, &mut requested.Privileges[0].Luid)
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context("无法查找 Windows 调试权限");
        }
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        let mut length = 0;
        // SAFETY: Both structures hold one privilege. Windows fills the previous-state buffer.
        // Clear last error because success can still mean ERROR_NOT_ALL_ASSIGNED.
        let success = unsafe {
            SetLastError(0);
            AdjustTokenPrivileges(
                guard.token.0,
                0,
                &requested,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut guard.previous,
                &mut length,
            )
        };
        let error = unsafe { GetLastError() };
        if success == 0 {
            return Err(std::io::Error::from_raw_os_error(error as i32))
                .context("无法启用 Windows 调试权限");
        }
        guard.restore = true;
        if error == ERROR_NOT_ALL_ASSIGNED {
            bail!("当前令牌没有 Windows 调试权限，可通过 UAC 以管理员身份启动后重新采集");
        }
        Ok(guard)
    }
}
impl Drop for DebugPrivilege {
    fn drop(&mut self) {
        if self.restore && self.previous.PrivilegeCount != 0 {
            // SAFETY: Restore only the exact attributes saved by this guard, while holding the lock.
            unsafe {
                AdjustTokenPrivileges(self.token.0, 0, &self.previous, 0, null_mut(), null_mut());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_capture_does_not_adjust_privileges() {
        let ctx = ExecutionContext::default();
        ctx.cancellation.cancel();
        let result = DebugPrivilege::acquire(&ctx);
        assert!(result.is_err_and(|error| crate::execution::is_cancelled(&error)));
    }

    #[test]
    fn restores_previous_privilege_attributes() {
        let ctx = ExecutionContext::default();
        let before_elevation = is_elevated().unwrap();
        if let Ok(first) = DebugPrivilege::acquire(&ctx) {
            let previous = (
                first.previous.PrivilegeCount,
                first.previous.Privileges[0].Attributes,
            );
            drop(first);
            // A second acquisition must observe the same pre-existing privilege state.
            let second = DebugPrivilege::acquire(&ctx).unwrap();
            assert_eq!(
                previous,
                (
                    second.previous.PrivilegeCount,
                    second.previous.Privileges[0].Attributes,
                )
            );
            drop(second);
        }
        // Ordinary accounts without SeDebugPrivilege must keep their original token too.
        assert_eq!(before_elevation, is_elevated().unwrap());
    }
}
