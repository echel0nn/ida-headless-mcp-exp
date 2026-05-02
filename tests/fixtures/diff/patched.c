#include <stdint.h>
#include <stddef.h>
#include <string.h>

struct packet {
    uint32_t magic;
    uint32_t length;
    uint8_t payload[64];
};

static int validate_length(uint32_t length) {
    return length <= 64;
}

int process_input(const uint8_t *buf, size_t len, struct packet *out) {
    if (!buf || !out) {
        return -1;
    }
    if (len < 8) {
        return -2;
    }

    out->magic = *(const uint32_t *)(buf + 0);
    out->length = *(const uint32_t *)(buf + 4);
    if (!validate_length(out->length)) {
        return -3;
    }
    memcpy(out->payload, buf + 8, out->length);
    return 0;
}


int main(void) {
    struct packet pkt = {0};
    uint8_t buf[72] = {0};
    return process_input(buf, sizeof(buf), &pkt);
}