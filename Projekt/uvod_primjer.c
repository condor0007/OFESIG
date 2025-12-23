#include <Windows.h>
#include <stdio.h>

int main() {
	printf("Shellcode");
    asm(".byte 0x90,0x90,0x90,0x90\n\t"
		".byte 0xC3\n\t");
    asm("nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "ret\n\t");
	return 0;
}


