#include <stdlib.h>
#include <string.h>

void handle_error(char *buf) {
    free(buf);
    /* bug: second free on same pointer */
    free(buf);
}

int main(void) {
    char *p = (char *)malloc(64);
    if (p) {
        memset(p, 'A', 64);
        handle_error(p);
    }
    return 0;
}
