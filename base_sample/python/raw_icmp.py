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
        if data[23] == 1:
            print("ICMP")
            src_ip = data[26:30]
            dst_ip = data[30:34]
            icmp_type = data[34]
            if icmp_type == 0:
                print("Echo Reply 正常")
            if icmp_type == 3:
                print("Destination Unreachable 宛先不明")
            if icmp_type == 8:
                print("Echo Request 要求")
            if icmp_type == 11:
                print("タイムアウト")
            print(f"Src IP: {parse_ip(src_ip)}")
            print(f"Dst IP: {parse_ip(dst_ip)}")
            print()


    
# filterオプションを省略することで、すべてのパケットをキャプチャ
sniff(prn=packet_callback, store=0)
