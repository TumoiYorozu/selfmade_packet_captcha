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
    
    if eth_type.hex() == '0806':
        print("Eth Type: ARP")

        # ARPヘッダーの解析
        op_code = data[20:22]

        src_mac = data[22:28]
        src_ip = data[28:32]
        dst_mac = data[32:38]
        dst_ip = data[38:42]

        # 表示
        if op_code.hex() == '0001':
            print("Request")
        if op_code.hex() == '0002':
            print("Reply")
        
            
        print(f"Src MAC: {parse_mac(src_mac)}, IP: {parse_ip(src_ip)}")
        print(f"Dst MAC: {parse_mac(dst_mac)}, IP: {parse_ip(dst_ip)}")
        print()
    
# filterオプションを省略することで、すべてのパケットをキャプチャ
sniff(prn=packet_callback, store=0)
