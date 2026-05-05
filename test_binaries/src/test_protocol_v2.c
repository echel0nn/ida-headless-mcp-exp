// Simplified protocol handler without winsock conflicts
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// Forward declare what we need from winsock
typedef unsigned int SOCKET;
#define INVALID_SOCKET (~0)
#define SOCKET_ERROR (-1)
#define AF_INET 2
#define SOCK_STREAM 1

// Import functions we call (linker resolves them)
__declspec(dllimport) int __stdcall recv(SOCKET s, char *buf, int len, int flags);
__declspec(dllimport) int __stdcall send(SOCKET s, const char *buf, int len, int flags);
__declspec(dllimport) int __stdcall closesocket(SOCKET s);

#define CMD_PING 0x01
#define CMD_EXEC 0x02
#define CMD_EXIT 0x04

__declspec(noinline)
void handle_command(SOCKET s, unsigned char cmd, char *data, int len) {
    char response[256];
    switch (cmd) {
        case CMD_PING: send(s, "PONG", 4, 0); break;
        case CMD_EXEC:
            snprintf(response, sizeof(response), "EXEC: %s", data);
            send(s, response, (int)strlen(response), 0);
            break;
        case CMD_EXIT: send(s, "BYE", 3, 0); break;
    }
}

__declspec(noinline)
void protocol_loop(SOCKET s) {
    char buf[4096];
    while (1) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (n >= 3) {
            unsigned char cmd = buf[0];
            unsigned short data_len = *(unsigned short*)(buf + 1);
            if (cmd == CMD_EXIT) { handle_command(s, cmd, 0, 0); break; }
            if (n >= 3 + data_len) handle_command(s, cmd, buf+3, data_len);
        }
    }
}

int main() {
    printf("Protocol handler ready\n");
    // Would normally connect here
    return 0;
}
