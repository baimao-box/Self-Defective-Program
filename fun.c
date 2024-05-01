#include <stdio.h>

void Vuln() {
	int a = 1;
}

void Jmp_Esp() {
	__asm__("jmp *%esp\n\t"
		"jmp *%eax\n\t"
		"pop %eax\n\t"
		"pop %eax\n\t"
		"ret");
}