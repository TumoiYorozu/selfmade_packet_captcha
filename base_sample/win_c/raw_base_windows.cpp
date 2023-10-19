#pragma warning(disable : 4995)
#pragma warning(disable : 4996)

#include <iostream>
#include <pcap.h>
#include <winsock2.h>

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* chosen_dev = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    int dev_num = -1;

    // 使用可能なデバイスを取得
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    // 接続済みのデバイスを表示
    {
        int i = 0;
        for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
            ++i;
            if (d->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED) {
                if (d->addresses == NULL) continue;
                std::cout << i << ": " << d->name << " - ";
                if (d->description) {
                    std::cout << d->description << std::endl;
                } else {
                    std::cout << "(no description)" << std::endl;
                }

                for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
                    if (a->addr->sa_family == AF_INET) {
                        struct sockaddr_in* sa = (struct sockaddr_in*)a->addr;
                        char* ip = inet_ntoa(sa->sin_addr);
                        std::cout << "   IP Address: " << ip << std::endl;
                        if (dev_num < 0) dev_num = i;
                    }
                }
            }
        }
    }

    // dev_num = 1;
    // ネットワークカードのデバイス番号を選択
    // std::cout << "Choose a device number: ";
    // std::cin >> dev_num;


    // デバイスの選択
    {
    int i = 1;
        for (pcap_if_t* d = alldevs; d != NULL && i <= dev_num; d = d->next, i++) {
            if (i == dev_num) {
                chosen_dev = d;
            }
        }
    }


    if (!chosen_dev) {
        std::cerr << "Device number not found." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // パケットをキャプチャするデバイスを開く
    pcap_t* adhandle;
    adhandle = pcap_open_live(chosen_dev->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) {
        std::cerr << "Unable to open the adapter. " << chosen_dev->name << " is not supported by WinPcap." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }


    std::cout << "\n\nListening on " << chosen_dev->description << "..." << std::endl;


    // パケットキャプチャ本体
    pcap_pkthdr* header;
    const u_char* data;
    int res;
    while ((res = pcap_next_ex(adhandle, &header, &data)) >= 0) {
        if (res == 0) {
            continue; // タイムアウト
        }

        // Ethernetタイプを表示
        int eth_type = data[12] * 256u + (unsigned char)data[13];


        // 受信したパケットの長さを表示
        printf("Received packet size: %d\n", header->len);

        printf("Ethernet Type: 0x%04x\n", eth_type);

        // 先頭の100バイトを16進数形式で表示
        for (int i = 0; i < (int)header->len; i++) {
            if (i >= 100) break;
            printf("%02x ", (unsigned char)data[i]);
        }
        printf("\n\n");
    }

    pcap_close(adhandle);
    pcap_freealldevs(alldevs);
    return 0;
}


