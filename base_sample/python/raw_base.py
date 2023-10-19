# pip3 install scapy
from scapy.all import sniff

def packet_callback(packet):
    # パケットをバイト形式に変換し、先頭の100バイトを取得
    data = bytes(packet)[:100]
    
    # 位置[12:14]にあるEthernetタイプを取得
    eth_type = data[12:14]
    print("Eth Type:", eth_type.hex())
    
    # パケットの簡単な要約
    print(packet.summary())
    
    # 16進数形式に変換し、バイトごとにスペースで区切る
    hex_output = ' '.join(["{:02x}".format(byte) for byte in data])
    print(hex_output)
    print()

    
# filterオプションを省略することで、すべてのパケットをキャプチャ
sniff(prn=packet_callback, store=0)
