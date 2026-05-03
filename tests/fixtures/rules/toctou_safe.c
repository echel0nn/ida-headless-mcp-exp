#include <stdio.h>
#include <stdlib.h>

void process_file(const char *path) {
    /* open directly -- no check-then-use race */
    FILE *f = fopen(path, "r");
    if (f) {
        char buf[256];
        fgets(buf, sizeof(buf), f);
        fclose(f);
    }
}

int main(void) {
    process_file("data.txt");
    return 0;
}
