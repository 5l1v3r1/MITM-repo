#!/usr/bin/python3.5

import sniff_func
import arp_poison
import extract
import ratio
import device_discovery
import carver
import sys
import os


def a_thing_that_makes_it_loop():
    functionality_screen()
    opt = int(user_input())
    choice_forwarder(opt)


def welcome():
    print("""
                             ####         ####
                            # /\ #########/ \ #     
                            # \             /#
                             #              #  
                      ####   # _ 0     0 _  #    ####
                     #    #  #  \________/  #   #    # 
                     #    #   #             #   #    #
            #######################################################
            #######################################################
                     __    __    _    _______   __    __
                    |  \  /  |  | |  |__   __| |  \  /  |
                    | | \/ | |  | |     | |    | | \/ | | 
                    | |\__/| |  | |     | |    | |\__/| |
                    | |    | |  | |     | |    | |    | |
                    | |    | |  | |     | |    | |    | |
                    |_|    |_|  |_|     |_|    |_|    |_|
            ############______by Joanna Orlowska______#############

    """)


def user_input():
    try:
        if sys.version_info[0] < 3:
            return int(raw_input("[>] Opt: "))
        else:
            return int(input("[>] Opt: "))
    except:
        x = user_input()
        choice_forwarder(x)


def functionality_screen():
    print("# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #")
    print("[+] 0: Install Dependencies.")
    print("[+] 1: Find Devices on this network.")
    print("[+] 2: Sniffer.")
    print("[+] 3: ARP poisoning.")
    print("[+] 4: Information Extraction (pcap file).")
    print("[+] 5: Protocol Ratio.")
    print("[+] 6: Carve Images (pcap file)")
    print("[+] 7: EXIT.")
    print("-------------------------------------------------------------------")


def choice_forwarder(opt):
    while opt != 7:
        if opt == 0:
            print("[+] Installing requirements: ")
            try:
                os.system("pip install -r requirements.txt")
            except:  ## Can add anther try statement here for permissions? or if apt not used? other os?
                os.system("sudo apt-get install pip")  ## possible trouble with sudo permissions?
                os.system("pip install -r requirements.txt")
            a_thing_that_makes_it_loop()

        elif opt == 1:
            device_discovery.host_discovery()

        elif opt == 2:
            print("[+] Packets: ")
            sniff_func.sniffer()

        elif opt == 3:
            arp_poison.arp_poison()

        elif opt == 4:
            extract.extract_info_from_pacp()

        elif opt == 5:
            ratio.p_ratio_static()

        elif opt == 6:
            carver.carver_input()

        elif opt is not 7:
            print("[-] Invalid Option.")
            functionality_screen()
            opt = user_input()
            choice_forwarder(opt)
            # /root/PycharmProjects/MITM/menu.py

    print("\n\n\n                                                 bye.\n")
    sys.exit(0)


if __name__ == "__main__":
    welcome()
    functionality_screen()
    opt = int(user_input())
    choice_forwarder(opt)




