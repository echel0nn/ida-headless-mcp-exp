#include <stdlib.h>
#include <string.h>

void run_user(const char *src) {
    char cmd[64] = {0};
    memcpy(cmd, src, 32);
    system(cmd);
}

int main(void) {
    char buf[64] = "calc.exe";
    run_user(buf);
    return 0;
}
