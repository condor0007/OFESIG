#include <windows.h>
#include <stdio.h>

int RunAsmLoop() {
    int result = 0;

    asm (
        "movl $0, %%eax\n\t"       // result = 0
        "movl $1, %%ecx\n\t"       // i = 1 
        
        "petlja:\n\t"
        "addl %%ecx, %%eax\n\t"    // result += i
        "incl %%ecx\n\t"           // i++
        "cmpl $10, %%ecx\n\t"      // je li i <= 10?
        "jle petlja\n\t"           // ako jest, skoči natrag na labelu 'petlja'
        
        : "=a" (result)            // Izlaz: vrijednost iz EAX registra ide u varijablu 'result'
        :                          // Ulaz: nema
        : "%ecx"                   // javljamo kompajleru da koristimo ECX
    );

    return result;
}

int main() {
    printf("Pocetak izvrsavanja asembler petlje...\n");

    // Pozivamo funkciju koja u sebi ima asembler
    int final_result = RunAsmLoop();
    
    printf("Rezultat shellcode petlje je: %d\n", final_result);
    printf("Program se nastavlja normalno.\n");

    return 0;
}