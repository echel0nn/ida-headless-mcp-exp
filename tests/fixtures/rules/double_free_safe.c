#include <stdlib.h>
#include <string.h>

void handle_error(char *buf) {
    free(buf);
    /* safe: pointer nulled after free */
    buf = NULL;
}

int main(void) {
    char *p = (char *)malloc(64);
    if (p) {
        memset(p, 'A', 64);
        handle_error(p);
    }
    return 0;
}
