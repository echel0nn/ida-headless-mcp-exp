#include <stdlib.h>
#include <string.h>

void alloc_items(unsigned int count, unsigned int item_size) {
    /* bug: multiplication can overflow before reaching malloc */
    unsigned int total = count * item_size;
    char *buf = (char *)malloc(total);
    if (buf) {
        memset(buf, 0, total);
        free(buf);
    }
}

int main(void) {
    alloc_items(0x10000001, 16);
    return 0;
}
