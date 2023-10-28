# pip3 install scapy
from scapy.all import sniff

def parse_mac(mac):
    return ':'.join(format(x, '02x') for x in mac)

def parse_ip(ip):
    return '.'.join(str(x) for x in ip)

def packet_callback(packet):
    # パケットをバイト形式に変換し、先頭の100バイトを取得
    data = bytes(packet)[:100]

    # 位置[12:14]にあるEthernetタイプを取得
    eth_type = data[12:14]
    
    if eth_type.hex() == '0800':
        # print("IP")
        if data[23] == 0x11:
            print("UDP")
            src_ip = data[26:30]
            dst_ip = data[30:34]
            
            length = data[38:40]
            
            body = data[42:]
            print(f"Sender IP: {parse_ip(src_ip)}")
            print(f"Target IP: {parse_ip(dst_ip)}")
            print(f"len: 0x{length.hex()}")
            print(f"body: {body}")
            print()


    
# filterオプションを省略することで、すべてのパケットをキャプチャ
sniff(prn=packet_callback, store=0)
