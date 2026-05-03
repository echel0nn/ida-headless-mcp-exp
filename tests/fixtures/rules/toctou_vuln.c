#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>

void process_file(const char *path) {
    /* check then use -- classic TOCTOU */
    if (_access(path, 0) == 0) {
        FILE *f = fopen(path, "r");
        if (f) {
            char buf[256];
            fgets(buf, sizeof(buf), f);
            fclose(f);
        }
    }
}

int main(void) {
    process_file("data.txt");
    return 0;
}
