// brew install libpcap
// clang++ -lpcap raw_base_mac.cpp
// sudo ./a.out


#include <iostream>
#include <pcap.h>

int main() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 利用可能なデバイスを列挙
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "pcap_findalldevs() failed: " << errbuf << std::endl;
        return 1;
    }

    // デバイスリストの最初のデバイスを使用
    device = alldevs;
    if (device == NULL) {
        std::cerr << "No devices found." << std::endl;
        return 1;
    }
    std::cout << "Using device: " << device->name << std::endl;

    // パケットをキャプチャするデバイスを開く
    pcap_t* adhandle;
    adhandle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (adhandle == NULL) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        pcap_freealldevs(alldevs); // リソースを解放
        return 1;
    }



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
    return 0;
}
