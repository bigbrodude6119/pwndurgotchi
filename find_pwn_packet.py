from scapy.all import *
import sys

source = SniffSource(iface="wlan0")
data_path = './data/pwn_packet'

def transf(pkt):

    source = pkt[Dot11].getfieldval("addr2")
    target = pkt[Dot11].getfieldval("addr1")
    
    if source == "de:ad:be:ef:de:ad" and target == "ff:ff:ff:ff:ff:ff":
        print("Starting packet saving!")
        wrpcap(data_path, pkt)
        print("Packet saved")
        sys.exit()

    return pkt

source > TransformDrain(transf)

p = PipeEngine(source)
p.start()
p.wait_and_stop()