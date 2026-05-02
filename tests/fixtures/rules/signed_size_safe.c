#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct blob {
    uint32_t length;
    uint8_t data[64];
};

static int validate_length(uint32_t length) {
    return length <= 64;
}

int process_blob(const uint8_t *src, struct blob *out) {
    if (!src || !out) {
        return -1;
    }
    out->length = *(const uint32_t *)(src + 0);
    if (!validate_length(out->length)) {
        return -2;
    }
    memcpy(out->data, src + 4, out->length);
    return 0;
}

int main(void) {
    struct blob b = {0};
    uint8_t src[68] = {0};
    return process_blob(src, &b);
}
