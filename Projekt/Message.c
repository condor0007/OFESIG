#include <windows.h>
#include <stdio.h>

int main() {
    char msg[] = "Sustav je zaražen!";
    char title[] = "Obavijest";
    
    
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28, 0x48, 0x31, 0xC9,                   
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x45, 0x31, 0xC9,                  
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3                               
    };

    LoadLibraryA("user32.dll"); // Obavezno jer MessageBox nije u kernel32
    void* msgbox_addr = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    void* msg_ptr = &msg;
    void* title_ptr = &title;

    memcpy(&shellcode[9], &msg_ptr, 8);
    memcpy(&shellcode[19], &title_ptr, 8);
    memcpy(&shellcode[32], &msgbox_addr, 8);

    void* exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    ((void(*)())exec_mem)();

    return 0;
}