use detour::static_detour;
use dns_lookup::lookup_host;
use std::error::Error;
use std::{ffi::CString, iter, mem};
use win32console::console::WinConsole;
use winapi::ctypes::c_int;
use winapi::shared::inaddr::IN_ADDR;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
use winapi::shared::ws2def::{SOCKADDR, SOCKADDR_IN};
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::um::winsock2::{htons, inet_addr, inet_ntoa, SOCKET};

const SHOW_CONSOLE: bool = true;
const REDIRECT_TO_IP: &str = "127.0.0.1";
const REDIRECT_TO_PORT: u16 = 15026;

static mut ips_to_redirect: Vec<String> = vec![];

static_detour! {
  static FnConnectHook: unsafe extern "system" fn(SOCKET, *const SOCKADDR, c_int) -> c_int;
}

type FnConnect = unsafe extern "system" fn(SOCKET, *const SOCKADDR, c_int) -> c_int;

#[no_mangle]
pub extern "C" fn lib_test() {
    unsafe {
        main().unwrap();
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _module: HINSTANCE,
    call_reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        winapi::um::consoleapi::AllocConsole();
        main().is_ok() as BOOL
    } else {
        TRUE
    }
}

fn write_console(str: &str) {
    if !SHOW_CONSOLE {
        return;
    }

    let msg = format!("{}\r\n", str);

    WinConsole::output().write_utf8(msg.as_bytes()).unwrap();
}

unsafe fn main() -> Result<(), Box<dyn Error>> {
    write_console("Fetching ips to redirect...");
    get_redirected_ip();

    write_console("Starting hooking...");

    let address = get_module_symbol_address("Ws2_32.dll", "connect")
        .expect("could not find 'connect' address");
    let target: FnConnect = mem::transmute(address);

    write_console(format!("hooked {}", &address.to_string()).as_str());

    // Initialize and enable the detour
    FnConnectHook.initialize(target, connect_detour)?.enable()?;
    Ok(())
}

/// Called whenever `connect` is invoked in the process.
fn connect_detour(s: SOCKET, name: *const SOCKADDR, namelen: c_int) -> c_int {
    unsafe {
        let mut addr_in: SOCKADDR_IN = std::ptr::read(name as *const _);

        let ip = inet_ntoa(addr_in.sin_addr);
        let port = addr_in.sin_port;

        // ip as str
        let ip = std::ffi::CStr::from_ptr(ip as *const i8)
            .to_str()
            .unwrap()
            .to_string();

        // port as str
        let port = port.to_be();
        let mut name_len = namelen;

        write_console(format!("connect {}:{}", ip, port).as_str());

        // check if ip is in ips_to_redirect
        if ips_to_redirect.contains(&ip) {
            write_console(format!("redirecting {}:{}", ip, port).as_str());
            // construct new sockaddr based on REDIRECT_TO_IP
            let ip_addr = inet_addr(REDIRECT_TO_IP.as_ptr() as *const i8);
            // convert u32 ip to array of u8 to be able to write it to sockaddr
            let ip_addr = std::mem::transmute::<u32, [u8; 4]>(ip_addr);
            // read the array as a IN_ADDR
            let ip_addr = std::ptr::read(ip_addr.as_ptr() as *const IN_ADDR);
            addr_in.sin_addr = ip_addr;
            addr_in.sin_port = htons(REDIRECT_TO_PORT);

            name_len = std::mem::size_of::<SOCKADDR_IN>() as c_int;
            // write to name ptr the new sockaddr so we can just call the original connect
            std::ptr::write(name as *mut _, addr_in);
        }

        // just to be sure we reread everything
        let addr_in: SOCKADDR_IN = std::ptr::read(name as *const _);
        let ip = inet_ntoa(addr_in.sin_addr);
        let port = addr_in.sin_port.to_be();

        // ip as str
        let ip = std::ffi::CStr::from_ptr(ip as *const i8)
            .to_str()
            .unwrap()
            .to_string();

        write_console(format!("to connect {}:{}", ip, port).as_str());

        FnConnectHook.call(s, name, name_len)
    }
}

fn get_redirected_ip() {
    let ip = lookup_host("dofus2-co-beta.ankama-games.com").unwrap();

    unsafe {
        for ip in ip {
            ips_to_redirect.push(ip.to_string());
            write_console(format!("ip: {}", ip).as_str());
        }
    }
}

/// Returns a module symbol's absolute address.
fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = module
        .encode_utf16()
        .chain(iter::once(0))
        .collect::<Vec<u16>>();
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        let handle = GetModuleHandleW(module.as_ptr());
        match GetProcAddress(handle, symbol.as_ptr()) as usize {
            0 => None,
            n => Some(n),
        }
    }
}
