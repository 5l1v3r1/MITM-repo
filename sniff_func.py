from scapy.all import *
import sys
import extract, menu, ratio

# packet = IP( dst = "1.2.3.4")



def sniffer():
    try:
        print("             ############_____________Sniffer____________############")
        if sys.version_info[0] < 3:
            in_ = raw_input("\t[>] Packet Count: \t\t")
            filter = raw_input("\t[>] Filter: (default tcp) \t")
            interface = raw_input("\t[>] Interface: (default wlo1) \t")
            flag = raw_input("\t[>] Extract information: (y/n)(default no) \t")
            fratio = raw_input("\t[>] Show Protocol Ratio: (y/n)(default no) \t")
            file = raw_input("\t[>] Path to file: (default on desktop) \t")
        else:
            in_ = input("\t[>] Packet Count: \t")
            filter = input("\t[>] Filter: (default tcp) \t")
            interface = input("\t[>] Interface: (default wlo1) \t")
            flag = input("\t[>] Extract information: (y/n)(default no) \t")
            fratio = input("\t[>] Show Protocol Ratio: (y/n)(default no) \t")
            file = input("\t[>] Path to file: (default on desktop) \t")

        if in_ == "" : in_ == 4999
        if interface == "": interface = "wlo1"
        if fratio == "": fratio = False
        else: fratio = True
        if file == "" : file = "/home/jo/Desktop/capture1.pcap"

        in_ = int(in_)
        print("\t\t[+] Starting sniffer.")
        start_pcap_sniffer(interface, filter, in_, flag, fratio, file)


        print("\t[+] Sniffer is done.\n")

        menu.a_thing_that_makes_it_loop()

    except Exception as e:
        print("[ERR] ", e)

def start_pcap_sniffer(interface, filter, in_, flag, fratio, file):
    if flag is True:
        packets = sniff(iface=interface, prn=callback, filter=filter, count=in_)
    else: packets = sniff(iface=interface, filter=filter, count=in_)

    print("\t[+] Writing packets to file.\n")
    wrpcap(file, packets)

    if fratio is True:
        ratio.p_ratio_rt(file)


def callback(p):
    extract.extract_info(p)
