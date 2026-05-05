// Test binary: simulates statically linked library functions
// Tests: detect_library_functions
// Note: We fake the library function names since we can't link actual OpenSSL here
#include <stdio.h>
#include <string.h>

// Fake OpenSSL-like function names (IDA FLIRT would recognize these)
__declspec(noinline) int SSL_read(void *ssl, void *buf, int num) {
    memset(buf, 'A', num > 0 ? num : 0);
    return num;
}

__declspec(noinline) int SSL_write(void *ssl, const void *buf, int num) {
    return num;
}

__declspec(noinline) void *SSL_CTX_new(void *method) {
    return (void*)0x12345678;
}

__declspec(noinline) void SSL_CTX_free(void *ctx) {}

// Fake zlib-like functions
__declspec(noinline) int deflate(void *strm, int flush) {
    return 0;
}

__declspec(noinline) int inflate(void *strm, int flush) {
    return 0;
}

__declspec(noinline) int deflateInit(void *strm, int level) {
    return 0;
}

// Fake CRC32
__declspec(noinline) unsigned long crc32_compute(unsigned long crc, const void *buf, unsigned int len) {
    const unsigned char *p = (const unsigned char*)buf;
    crc = crc ^ 0xFFFFFFFF;
    for (unsigned int i = 0; i < len; i++) {
        crc = (crc >> 8) ^ (0xEDB88320 & -(int)((crc ^ p[i]) & 1));
    }
    return crc ^ 0xFFFFFFFF;
}

int main() {
    void *ctx = SSL_CTX_new(NULL);
    char buf[64];
    SSL_read(ctx, buf, 64);
    SSL_write(ctx, "hello", 5);
    SSL_CTX_free(ctx);

    deflateInit(NULL, 6);
    deflate(NULL, 0);
    inflate(NULL, 0);

    printf("CRC32: 0x%08lx\n", crc32_compute(0, "test", 4));
    return 0;
}
