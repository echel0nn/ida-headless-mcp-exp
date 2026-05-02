#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct blob {
    int32_t length;
    uint8_t data[64];
};

int process_blob(const uint8_t *src, struct blob *out) {
    if (!src || !out) {
        return -1;
    }
    out->length = *(const int32_t *)(src + 0);
    memcpy(out->data, src + 4, out->length);
    return 0;
}

int main(void) {
    struct blob b = {0};
    uint8_t src[68] = {0};
    return process_blob(src, &b);
}
