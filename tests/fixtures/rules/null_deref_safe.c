#include <stdlib.h>
#include <string.h>

void parse_data(size_t n) {
    char *buf = (char *)malloc(n);
    /* safe: NULL check present */
    if (buf) {
        memset(buf, 0, n);
        buf[0] = 'A';
        free(buf);
    }
}

int main(void) {
    parse_data(1024);
    return 0;
}
