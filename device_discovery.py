import re, os, subprocess, texttable as tt
import menu

def host_discovery():
    print("            ############________Device_Discovery________############")

    subprocess.call("/root/PycharmProjects/MITM/prober.sh")

    pc_name = "(?<=)(.*?)(?=\ \()"
    ip_address = "(?<= \()(.*?)(?=\) )"
    mac_address = "(?<= at )(.*?)(?= \[)"

    f = "/root/PycharmProjects/MITM/hosts2.txt"

    file = open(f, "r").readlines() ## does it read it in befor done probing because of the '&'?
    hosts = []

    for i in range(len(file)):
        if ((not file[i].startswith("? ")) and (file[i].find("incomplete") < 0)):

            local_host = []
            local_host.append(re.search(pc_name, file[i]).group())
            local_host.append(re.search(ip_address, file[i]).group())
            local_host.append(re.search(mac_address, file[i]).group())
            if local_host not in hosts:
                hosts.append(local_host)

    try:

        tab = tt.Texttable()
        headings =  ["Device", "IP", "MAC"]
        tab.header(headings)

        for i in hosts:
            tab.add_row((i[0], i[1], i[2]))
        print(tab.draw())
    except:
        print("[ERR]: texttable module not installed.")

    print("==============================================================")
    os.system("ip route | grep default")
    print("==============================================================")

    os.system("ip link set arp off dev wlo1: ip link set arp on dev wlo1") ## depending on device ran from. may break + needs sudo access


    menu.a_thing_that_makes_it_loop()
