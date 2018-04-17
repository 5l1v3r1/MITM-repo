from scapy.all import *
import re, texttable as tt
import menu

dict = {
    "FTP":"20",
    "FTP":"21",
    "SSH":"22",
    "telnet":"23",
    "SMTP":"25",
    "DNS":"53",
    "DHCP":"67",
    "DHCP":"68",
    "TFTP":"69",
    "HTTP":"80",
    "POPv3":"110",
    "NTP":"123",
    "IMAP":"143",
    "SNMP":"161",
    "SNMP":"162",
    "BGP":"179",
    "LDAP":"389",
    "HTTPS":"443",
    "LDAP":"636",
    "FTPoverTLS/SSL":"989",
    "FTPoverTLS/SSL":"990"
}
ratios = {}

def p_ratio_rt(filename):
    main_extraction(filename)

def to_string(nr):
    for k, v in dict.items():
        if int(v) is int(nr):
            return k
    return nr

def p_ratio_static():
    print("            ############_________Protocol_Ratio_________############")

    try:
        if sys.version_info[0] < 3:
            file = raw_input("\t[>] Path to file: (default on desktop) \t")
        else:
            file = input("\t[>] Path to file: (default on desktop) \t")

        if file == "" : file = "/home/jo/Desktop/capture1.pcap"

    except Exception as e:
        print("[ERR]: Something went wrong with the user input. Please try again: ", e)

    main_extraction(file)


def main_extraction(filename):
    all_occurences = []
    file_regex = re.search(r"(?:.*/)(.*)(?=)", filename).group(1)
    print("\t[+] Extracting protocols from: %s" % (file_regex))
    regex = r"(?<=sport=|dport=)(.*?)(?=\,|\))"

    for p in PcapReader(filename):

        if Ether in p:#check for tcp too?
            p_str = p.command()

            if re.search(regex, p_str):
                all_occurences.append(re.search(regex, p_str).group(0))
                all_occurences.append(re.search(regex, p_str).group(1))

    for i in all_occurences:
        if int(i) < 1024: #0-1023 are registered ports
            ratios.update({to_string(i): all_occurences.count(i)})

    #print(ratios)

    # [expression for item in list]
    try:

        tab = tt.Texttable()
        headings =  ["Protocol", "# of Packets"]
        tab.header(headings)

        for k,v in ratios.items():
            tab.add_row((k, v))

        print("\n")
        print(tab.draw())
        print("\n")
    except:
        print("[ERR]: texttable module not installed or something went wrong.")



    menu.a_thing_that_makes_it_loop()

