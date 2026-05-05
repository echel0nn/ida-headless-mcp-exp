// Test binary: stack-constructed strings
// Tests: detect_stack_strings
#include <windows.h>
#include <stdio.h>

// Construct strings on stack to evade static analysis
__declspec(noinline)
void hidden_command(void) {
    // Build "cmd.exe /c whoami" on stack
    char cmd[20];
    cmd[0] = 'c';
    cmd[1] = 'm';
    cmd[2] = 'd';
    cmd[3] = '.';
    cmd[4] = 'e';
    cmd[5] = 'x';
    cmd[6] = 'e';
    cmd[7] = ' ';
    cmd[8] = '/';
    cmd[9] = 'c';
    cmd[10] = ' ';
    cmd[11] = 'w';
    cmd[12] = 'h';
    cmd[13] = 'o';
    cmd[14] = 'a';
    cmd[15] = 'm';
    cmd[16] = 'i';
    cmd[17] = '\0';

    printf("Running: %s\n", cmd);
}

__declspec(noinline)
void hidden_url(void) {
    // Build URL on stack
    char url[64];
    url[0] = 'h'; url[1] = 't'; url[2] = 't'; url[3] = 'p';
    url[4] = ':'; url[5] = '/'; url[6] = '/';
    url[7] = '1'; url[8] = '0'; url[9] = '.';
    url[10] = '0'; url[11] = '.'; url[12] = '0';
    url[13] = '.'; url[14] = '1';
    url[15] = '/'; url[16] = 'b'; url[17] = 'e';
    url[18] = 'a'; url[19] = 'c'; url[20] = 'o';
    url[21] = 'n'; url[22] = '\0';

    printf("URL: %s\n", url);
}

__declspec(noinline)
void hidden_registry_key(void) {
    // Build registry path with DWORD packing
    // "SOFTWARE\Microsoft" packed as DWORDs
    unsigned int parts[5];
    parts[0] = 0x54464F53;  // "SOFT"
    parts[1] = 0x45524157;  // "WARE"
    parts[2] = 0x694D5C5C;  // "\\Mi"  (note: backslash)
    parts[3] = 0x736F7263;  // "cros"
    parts[4] = 0x0074666F;  // "oft\0"

    char *key = (char*)parts;
    printf("Key: %s\n", key);
}

int main() {
    hidden_command();
    hidden_url();
    hidden_registry_key();
    return 0;
}
