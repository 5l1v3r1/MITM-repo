from scapy.all import *
import sys, re
import menu

dict_uname = ['username=', 'user=', 'login=', 'usr=']
dict_pass = ['password=', 'pass=']
dict_origin = ['Host:', 'Referer:']
dict_pass_ending = ['&', '\')', '\r' ]
dict_unwanted = ['deleted', ' ']

prev = []

regex_username_dictionary = [r'(?<=login=)(.*?)(?=\&)']


def extract_info(p):
    new_v = sys_check()

    if Raw in p:
        contents = p[Raw].command() # the string representation of the contents of the Raw field of the passed in packet
        #contents = p.command() # the string representation of the contents of the Raw field of the passed in packet
        contents = str(contents)

        if "POST" in contents:
            #print(contents)

            if re.search('(?<=Host:)(.*?)(?=\\\\r\\\\n)', contents):
                s = "\n\t[ORIGIN]: " + re.search('(?<=Host:)(.*?)(?=\\\\r\\\\n)', contents).group(0)
                if check_prev(s):
                    print(s)
            elif re.search('(?<=Referer: )(.*?)(?=\\\\r\\\\n)', contents):
                s = "\n\t[ORIGIN]: " + re.search('(?<=Referer: )(.*?)(?=\\\\r\\\\n)', contents).group(0)
                if check_prev(s):
                    print(s)

            if re.search('(?<=login=)(.*?)(?=\&)', contents):
                s = "\t[UNAME]:    " + re.search('(?<=login=)(.*?)(?=\&)', contents).group(0)
                if check_prev(s):
                    print(s)
            elif re.search('(?<=username=)(.*?)(?=\&)', contents):
                s = "\t[UNAME]:    " + re.search('(?<=login=)(.*?)(?=\&)', contents).group(0)
                if check_prev(s):
                    print(s)
            elif re.search('(?<=user=)(.*?)(?=\&)', contents):
                s = "\t[UNAME]:    " + re.search('(?<=login=)(.*?)(?=\&)', contents).group(0)
                if check_prev(s):
                    print(s)
            elif re.search('(?<=usr=)(.*?)(?=\&)', contents):
                s = "\t[UNAME]:    " + re.search('(?<=login=)(.*?)(?=\&)', contents).group(0)
                if check_prev(s):
                    print(s)
            elif re.search('(?<=nid=)(.*?)(?=\&)', contents):
                s = "\t[UNAME]:   " + re.search('(?<=nid=)(.*?)(?=\&)', contents).group(0)
                if check_prev(s):
                    print(s)

            if re.search('(?<=password=)(.*?)(?=\\\'\))', contents):
                s = "\t[PASS]:    " + re.search('(?<=password=)(.*?)(?=\\\'\))', contents).group(0)
                if check_prev(s):
                    print(s)
            elif re.search('(?<=pass=)(.*?)(?=\&)', contents):
                s = "\t[PASS]:    " + re.search('(?<=pass=)(.*?)(?=\&)', contents).group(0)
                if check_prev(s):
                    print(s)
            elif re.search('(?<=passwd=)(.*?)(?=\&)', contents):
                s = "\t[PASS]:    " + re.search('(?<=passwd=)(.*?)(?=\&)', contents).group(0)
                if check_prev(s):
                    print(s)

def check_prev(a):
    if prev.count(a) < 1:
        prev.append(a)
        return True
    else: return False

def extract_info_from_pacp():
    print("             ############______Extract_Info_From_PCAP____############")
    print("[+] Extracting information from pcap file:")

    if sys.version_info[0] < 3:
        file = raw_input("[>] PCAP File Location: \t")
    else:
        file = input("[>] PCAP File Location: \t")

    if file is "": file = "/home/jo/Desktop/capture1.pcap"

    for p in PcapReader(file):
        extract_info(p)
    print("\n")

    menu.a_thing_that_makes_it_loop()


def sys_check():
    try:
        if sys.version_info[0] < 3:
            return False
        else:
           return True

    except Exception as e:
        print("[ERR] ", e)
