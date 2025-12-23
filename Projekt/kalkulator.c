#include <windows.h>
#include <stdio.h>

int main() {
    char command[] = "calc.exe";
    
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                         
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, <ADDR_COMMAND>
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,       
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <ADDR_WINEXEC>
        0xFF, 0xD0,                                     
        0x48, 0x83, 0xC4, 0x28,                         
        0xC3                                            
    };

    void* cmd_addr = &command;
    void* winexec_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");

    // unos vrijednosti adresa u shellcode
    memcpy(&shellcode[6], &cmd_addr, 8);      
    memcpy(&shellcode[23], &winexec_addr, 8); 

   
    void* exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    
    ((void(*)())exec_mem)();

    return 0;
}