// Test binary: API hash resolution via ROR13
// Tests: resolve_api_hashes (107 algorithms)
#include <windows.h>
#include <stdio.h>

// ROR13 hash function (common shellcode technique)
__declspec(noinline)
unsigned int ror13_hash(const char *name) {
    unsigned int hash = 0;
    while (*name) {
        hash = ((hash >> 13) | (hash << 19)) + *name;
        name++;
    }
    return hash;
}

// Resolve API by hash
__declspec(noinline)
void *resolve_api(HMODULE mod, unsigned int target_hash) {
    // Walk export table manually (simplified)
    // In real malware this walks PEB -> LDR -> modules -> exports
    // For testing, we just call GetProcAddress with known names
    // but the HASH CONSTANTS are what we want to detect

    // These are the hash values that resolve_api_hashes should find:
    unsigned int hashes[] = {
        0x16b3fe72,  // CreateProcessA (ror13_add)
        0x0e8afe98,  // VirtualAlloc (ror13_add)
        0x0c917432,  // LoadLibraryA (ror13_add)
        0x7c0dfcaa,  // GetProcAddress (ror13_add)
        0x876f8b31,  // WinExec (ror13_add)
        0x6ba6bcc9,  // WriteFile (ror13_add)
    };

    for (int i = 0; i < 6; i++) {
        if (hashes[i] == target_hash) {
            // Found — in real code this would return the API pointer
            return (void*)(uintptr_t)hashes[i];
        }
    }
    return NULL;
}

int main() {
    printf("ROR13('kernel32.dll') = 0x%08x\n", ror13_hash("kernel32.dll"));
    printf("ROR13('CreateProcessA') = 0x%08x\n", ror13_hash("CreateProcessA"));
    printf("ROR13('VirtualAlloc') = 0x%08x\n", ror13_hash("VirtualAlloc"));

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    void *api = resolve_api(k32, 0x16b3fe72);
    printf("Resolved: %p\n", api);
    return 0;
}
