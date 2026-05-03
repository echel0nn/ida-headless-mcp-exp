#include <stdint.h>
#include <stdio.h>
#include <string.h>

void log_user(const char *src) {
    char fmt[64] = {0};
    memcpy(fmt, src, 32);
    printf("%s", fmt);
}

int main(void) {
    char buf[64] = "%s%s%s%s";
    log_user(buf);
    return 0;
}
