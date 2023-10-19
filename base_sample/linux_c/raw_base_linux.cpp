#include <iostream>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <cstring>
#include <linux/if_ether.h>

int main() {
    // Raw socketの作成
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        printf("Error creating raw socket. Root permissions might be required.\n");
        return -1;
    }

    char data[4096];
    memset(data, 0, sizeof(data));

    // 全てのタイプのパケットの受信
    while (true) {
        ssize_t data_size = recv(sockfd, data, sizeof(data), 0);
        if (data_size < 0) {
            printf("Failed to get packets\n");
            return -1;
        }

        // 受信したパケットの長さを表示
        printf("Received packet size: %zd\n", data_size);

        // Ethernetタイプを表示
        int eth_type = data[12] * 256u + (unsigned char)data[13];
        printf("Ethernet Type: 0x%04x\n", eth_type);

        // 先頭の100バイトを16進数形式で表示
        for (int i = 0; i < data_size; i++) {
            if (i >= 100) break;
            printf("%02x ", (unsigned char)data[i]);
        }
        printf("\n\n");

    }

    close(sockfd);
    return 0;
}
