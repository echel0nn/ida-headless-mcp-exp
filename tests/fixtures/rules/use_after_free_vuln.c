#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void cleanup_and_log(char *buf) {
    free(buf);
    /* bug: use after free */
    printf("freed buffer: %s\n", buf);
}

int main(void) {
    char *p = (char *)malloc(64);
    if (p) {
        strcpy(p, "hello");
        cleanup_and_log(p);
    }
    return 0;
}
