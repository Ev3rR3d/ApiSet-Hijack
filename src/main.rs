#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::collections::HashSet;
use std::ffi::c_void;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;


use winapi::um::accctrl::SE_FILE_OBJECT;
use winapi::um::aclapi::GetNamedSecurityInfoW;
use winapi::shared::sddl::{ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1};
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

// --- Estruturas ApiSet ---
#[repr(C)]
pub struct API_SET_NAMESPACE {
    pub Version: u32,
    pub Size: u32,
    pub Flags: u32,
    pub Count: u32,
    pub EntryOffset: u32,
    pub HashOffset: u32,
    pub HashFactor: u32,
}

#[repr(C)]
pub struct API_SET_NAMESPACE_ENTRY {
    pub Flags: u32,
    pub NameOffset: u32,
    pub NameLength: u32,
    pub HashedLength: u32,
    pub ValueOffset: u32,
    pub ValueCount: u32,
}

// --- Estruturas PE ---
#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_SECTION_HEADER {
    Name: [u8; 8],
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
}

#[repr(C)]
struct IMAGE_IMPORT_DESCRIPTOR {
    OriginalFirstThunk: u32,
    TimeDateStamp: u32,
    ForwarderChain: u32,
    Name: u32,
    FirstThunk: u32,
}

// --- Funções de Segurança / SDDL ---
fn get_directory_sddl(dir: &Path) -> Option<String> {
    let wide_path: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut p_sd: PSECURITY_DESCRIPTOR = null_mut();
    
    unsafe {
        let status = GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut p_sd,
        );

        if status != 0 || p_sd.is_null() {
            return None;
        }

        let mut sddl_ptr: *mut u16 = null_mut();
        let mut sddl_len: u32 = 0;

        let success = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            p_sd,
            SDDL_REVISION_1 as u32, // Cast explícito de u8 para u32
            DACL_SECURITY_INFORMATION,
            &mut sddl_ptr,
            &mut sddl_len,
        );

        LocalFree(p_sd as *mut _);

        if success == 0 || sddl_ptr.is_null() {
            return None;
        }

        let sddl_slice = std::slice::from_raw_parts(sddl_ptr, sddl_len as usize);
        let sddl_string = String::from_utf16_lossy(sddl_slice);
        
        LocalFree(sddl_ptr as *mut _);
        
        Some(sddl_string.trim_end_matches('\0').to_string())
    }
}

fn is_sddl_vulnerable(sddl: &str) -> bool {
    let weak_sids = ["BU", "AU", "WD"]; // Users, Auth Users, Everyone
    let weak_rights = ["FA", "FC", "MA", "GW", "GA", "WD", "WO"];

    for ace in sddl.split('(').skip(1) { 
        let parts: Vec<&str> = ace.split(';').collect();
        if parts.len() >= 6 {
            let ace_type = parts[0];
            let rights = parts[2];
            let sid = parts[5].trim_end_matches(')');

            if ace_type == "A" && weak_sids.contains(&sid) {
                for right in &weak_rights {
                    if rights.contains(right) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// --- Core do Scanner ---
#[cfg(target_arch = "x86_64")]
unsafe fn get_apiset_map() -> *mut API_SET_NAMESPACE {
    unsafe {
        let peb_ptr: *mut c_void;
        std::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb_ptr,
            options(readonly, nostack, preserves_flags)
        );
        let apiset_ptr = (peb_ptr as *const u8).add(0x68) as *const *mut API_SET_NAMESPACE;
        *apiset_ptr
    }
}

fn rva_to_offset(rva: u32, buffer: &[u8], nt_headers_offset: usize) -> Option<usize> {
    if rva == 0 { return None; }
    
    unsafe {
        let file_header_offset = nt_headers_offset + 4;
        if file_header_offset + 20 > buffer.len() { return None; }

        let number_of_sections = u16::from_le_bytes(buffer[file_header_offset + 2..file_header_offset + 4].try_into().unwrap()) as usize;
        let size_of_optional_header = u16::from_le_bytes(buffer[file_header_offset + 16..file_header_offset + 18].try_into().unwrap()) as usize;
        
        let section_table_offset = file_header_offset + 20 + size_of_optional_header;

        for i in 0..number_of_sections {
            let section_offset = section_table_offset + (i * std::mem::size_of::<IMAGE_SECTION_HEADER>());
            if section_offset + std::mem::size_of::<IMAGE_SECTION_HEADER>() > buffer.len() { break; }
            
            let section = &*(buffer.as_ptr().add(section_offset) as *const IMAGE_SECTION_HEADER);
            
            let va = section.VirtualAddress;
            let vsize = if section.VirtualSize > 0 { section.VirtualSize } else { section.SizeOfRawData };
            
            if rva >= va && rva < va + vsize {
                return Some((rva - va + section.PointerToRawData) as usize);
            }
        }
    }
    None
}

fn scan_pe_imports(file_path: &Path, whitelist: &HashSet<String>) {
    let buffer = match fs::read(file_path) {
        Ok(b) => b,
        Err(_) => return,
    };

    if buffer.len() < std::mem::size_of::<IMAGE_DOS_HEADER>() { return; }

    unsafe {
        let dos_header = &*(buffer.as_ptr() as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D { return; }

        let e_lfanew = dos_header.e_lfanew as usize;
        if e_lfanew + 24 > buffer.len() { return; }

        let signature = u32::from_le_bytes(buffer[e_lfanew..e_lfanew + 4].try_into().unwrap());
        if signature != 0x4550 { return; }

        let magic = u16::from_le_bytes(buffer[e_lfanew + 24..e_lfanew + 26].try_into().unwrap());
        let data_dir_offset = match magic {
            0x10B => e_lfanew + 24 + 96,
            0x20B => e_lfanew + 24 + 112,
            _ => return,
        };

        if data_dir_offset + 8 > buffer.len() { return; }

        let import_dir_rva = u32::from_le_bytes(buffer[data_dir_offset..data_dir_offset + 4].try_into().unwrap());
        if import_dir_rva == 0 { return; }

        let import_dir_offset = match rva_to_offset(import_dir_rva, &buffer, e_lfanew) {
            Some(offset) => offset,
            None => return,
        };

        let mut current_descriptor_offset = import_dir_offset;

        loop {
            if current_descriptor_offset + std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() > buffer.len() { break; }
            let descriptor = &*(buffer.as_ptr().add(current_descriptor_offset) as *const IMAGE_IMPORT_DESCRIPTOR);
            
            if descriptor.Name == 0 && descriptor.FirstThunk == 0 { break; }
            
            if let Some(name_offset) = rva_to_offset(descriptor.Name, &buffer, e_lfanew) {
                if name_offset < buffer.len() {
                    let mut name_end = name_offset;
                    while name_end < buffer.len() && buffer[name_end] != 0 {
                        name_end += 1;
                    }
                    
                    if let Ok(dll_name) = std::str::from_utf8(&buffer[name_offset..name_end]) {
                        let dll_lower = dll_name.to_lowercase();
                        
                        if dll_lower.starts_with("api-ms-") || dll_lower.starts_with("ext-ms-") {
                            if !whitelist.contains(&dll_lower) {
                                let parent_dir = file_path.parent().unwrap_or_else(|| Path::new(""));
                                
                                if let Some(sddl) = get_directory_sddl(parent_dir) {
                                    if is_sddl_vulnerable(&sddl) {
                                        println!("[!!!] 0-DAY LÓGICO DE LPE CONFIRMADO!");
                                        println!("  [>] Alvo: {}", file_path.display());
                                        println!("  [>] Gap:  {}", dll_lower);
                                        println!("  [>] SDDL: {}", sddl);
                                        println!("  [>] Ação: Diretório gravável (Users/AuthUsers). Drop autorizado.\n");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            current_descriptor_offset += std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        }
    }
}

fn walk_directory(dir: &Path, whitelist: &HashSet<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let p_str = path.to_string_lossy().to_lowercase();
                if p_str.contains("windows") { continue; } 
                walk_directory(&path, whitelist);
            } else if let Some(ext) = path.extension() {
                if ext == "exe" || ext == "dll" {
                    scan_pe_imports(&path, whitelist);
                }
            }
        }
    }
}

fn main() {
    unsafe {
        let map = get_apiset_map();
        if map.is_null() {
            println!("[-] Falha: ApiSetMap retornou NULL.");
            return;
        }

        let map_base = map as *const u8;
        let entries_ptr = map_base.add((*map).EntryOffset as usize) as *const API_SET_NAMESPACE_ENTRY;
        let mut valid_apisets = HashSet::new();

        for i in 0..(*map).Count {
            let entry = &*entries_ptr.add(i as usize);
            let name_slice = std::slice::from_raw_parts(
                map_base.add(entry.NameOffset as usize) as *const u16,
                (entry.NameLength / 2) as usize
            );
            let api_name = String::from_utf16_lossy(name_slice).to_lowercase();
            valid_apisets.insert(format!("{}.dll", api_name));
        }

        println!("[+] Scanner Iniciado.");
        println!("[+] {} namespaces nativos carregados na Whitelist.", valid_apisets.len());
        println!("[*] Varrendo diretórios em busca de ApiSet Gaps com ACLs vulneráveis...\n");

        walk_directory(Path::new("C:\\Windows\\System32\\"), &valid_apisets);
        //walk_directory(Path::new("C:\\Program Files"), &valid_apisets);
        //walk_directory(Path::new("C:\\Program Files (x86)"), &valid_apisets);
        
        println!("[+] Varredura concluída.");
    }
}