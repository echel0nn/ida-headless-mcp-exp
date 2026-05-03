#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void cleanup_and_log(char *buf) {
    printf("freeing buffer: %s\n", buf);
    /* safe: use before free */
    free(buf);
}

int main(void) {
    char *p = (char *)malloc(64);
    if (p) {
        strcpy(p, "hello");
        cleanup_and_log(p);
    }
    return 0;
}
