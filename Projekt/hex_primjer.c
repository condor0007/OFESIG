#include <windows.h>
#include <stdio.h>

int main() {
     // Heksadecimalni niz koji implementira petlju za zbrajanje brojeva od 1 do 10
    unsigned char shellcode[] = 
        "\x55\x48\x89\xe5\x48\x83\xec\x10\xc7\x45"
        "\xfc\x00\x00\x00\x00\xc7\x45\xf8\x01\x00"
        "\x00\x00\xeb\x0a\x8b\x45\xf8\x01\x45\xfc"
        "\x83\x45\xf8\x01\x83\x7d\xf8\x0a\x7e\xf0"
        "\x8b\x45\xfc\xc9\xc3\x90\x90\x90";                                 

    printf("Pocetak izvrsavanja...\n");

    // 1. Alokacija memorije
    LPVOID exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) return 1;
    printf("Memorija alocirana na adresi: %p\n", exec_mem);
    // 2. Kopiranje hex koda u tu memoriju
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    // 3. Definisanje tipa funkcije koja vraca int (jer tvoj Shellcode() vraca int)
    printf("Izvrsavanje shellcode petlje...\n");
    typedef int (*ShellcodeFunc)();
    ShellcodeFunc execute = (ShellcodeFunc)exec_mem;
    printf("Shellcode petlja izvrsena.\n");
    // 4. Pozivanje i hvatanje rezultata
    int final_result = execute();
    
    printf("Rezultat shellcode petlje je: %d\n", final_result);
    printf("Program se nastavlja normalno.\n");
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}