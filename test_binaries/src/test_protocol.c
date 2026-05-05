// Test binary: network protocol state machine
// Tests: detect_protocol_state_machine, capa_scan, classify_behavior
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

#define CMD_PING    0x01
#define CMD_EXEC    0x02
#define CMD_UPLOAD  0x03
#define CMD_EXIT    0x04

__declspec(noinline)
void handle_command(SOCKET s, unsigned char cmd, char *data, int len) {
    char response[256];
    switch (cmd) {
        case CMD_PING:
            send(s, "PONG", 4, 0);
            break;
        case CMD_EXEC:
            // Execute command (simulated)
            snprintf(response, sizeof(response), "EXEC: %.200s", data);
            send(s, response, (int)strlen(response), 0);
            break;
        case CMD_UPLOAD:
            // Write data to file (simulated)
            snprintf(response, sizeof(response), "UPLOAD: %d bytes", len);
            send(s, response, (int)strlen(response), 0);
            break;
        case CMD_EXIT:
            send(s, "BYE", 3, 0);
            break;
    }
}

__declspec(noinline)
void protocol_loop(SOCKET s) {
    char buf[4096];
    int state = 0;  // 0=wait_header, 1=wait_data

    while (1) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;

        // Protocol: [1 byte cmd] [2 byte len] [data]
        if (n >= 3) {
            unsigned char cmd = buf[0];
            unsigned short data_len = *(unsigned short*)(buf + 1);

            if (cmd == CMD_EXIT) {
                handle_command(s, cmd, NULL, 0);
                break;
            }

            if (n >= 3 + data_len) {
                handle_command(s, cmd, buf + 3, data_len);
            }
        }
    }
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        protocol_loop(s);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
