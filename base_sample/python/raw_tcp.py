# pip3 install scapy
from scapy.all import sniff

def parse_mac(mac):
    return ':'.join(format(x, '02x') for x in mac)

def parse_ip(ip):
    return '.'.join(str(x) for x in ip)

def packet_callback(packet):
    # パケットをバイト形式に変換し、先頭の100バイトを取得
    data = bytes(packet)[:2000]

    # 位置[12:14]にあるEthernetタイプを取得
    eth_type = data[12:14]
    
    if eth_type.hex() == '0800':
        # print("IP")
        if data[23] == 0x06:
            print("TCP")
            src_ip = data[26:30]
            dst_ip = data[30:34]
            
            head_length = (data[46] >> 4) * 4
            
            body = data[(34 + head_length):]
            print(f"Sender IP: {parse_ip(src_ip)}")
            print(f"Target IP: {parse_ip(dst_ip)}")
            print(f"head_length: {head_length}")
            
            print(f"body: {body}")
            print()


    
# filterオプションを省略することで、すべてのパケットをキャプチャ
sniff(prn=packet_callback, store=0)
