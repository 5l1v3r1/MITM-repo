#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import menu

def http_assembler(pcap_file, path):
    pictures_directory = path
    pcap_file = re.search(r"(?:.*/)(.*)(?=)", pcap_file).group(0)
    carved_images  = 0
    dupes = []

    print("\t\t[+] Reading in the pcap file.")
    a = rdpcap(pcap_file)
    print("\t\t[+] Finished reading the file.")
    sessions = a.sessions()

    for session in sessions:

        http_payload = ""
        image_payload = bytes()

        for packet in sessions[session]:

            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    string_payload = str(packet[TCP].payload)
                    encoded = bytes(packet[TCP].payload)

                    #prevents duplicates from being added to the http_payload
                    if string_payload[len(string_payload)-30:] not in dupes:
                        dupes.append(string_payload[len(string_payload)-30:])

                        condition_a = bytes("Last-Modified", "utf8") in encoded or bytes("Accept-Ranges", "utf8") in encoded # if headers
                        condition_b = bytes("</html>\r\n", "utf8") in encoded or bytes("DOCTYPE", "utf8") in encoded or bytes("<html", "utf8") in encoded# if html
                        condition_jpeg = bytes("image/jpeg", "utf8") in encoded or bytes("image/jpg", "utf8") in encoded
                        condition_png = bytes("image/png", "utf8") in encoded
                        condition_gif = bytes("image/gif", "utf8") in encoded
                        condition_gzip = bytes("gzip", "utf8") in encoded

                        if condition_a: # if headers
                            image_payload += encoded[encoded.find(bytes("\r\n\r\n", "utf8")) + 4:]
                            # if condition_jpeg:
                            #     image_payload += encoded[encoded.find(bytes("g\r\n\r\n", "utf8")) + 5:]
                            # if condition_png:
                            #     image_payload += encoded[encoded.find(bytes("png\r\n\r\n", "utf8")) + 7:]
                            # if condition_gif:
                            #     image_payload += encoded[encoded.find(bytes("gif\r\n\r\n", "utf8")) + 7:]
                            # if condition_gzip:
                            #     #print("dang") # *******************fix here!!!
                            #     image_payload += encoded[encoded.find(bytes("Content-Encoding: gzip\r\n\r\n", "utf8")) + 26:]
                            # if not condition_gif and not condition_png and not condition_jpeg and bytes("Content-Type: image", "utf8") in encoded:
                            #     print("\t\t[***] Possible error when extracting an image.")

                        if condition_b: # if html
                            if bytes("</html>\r\n", "utf8") in encoded:
                                image_payload += image_payload[image_payload.find(bytes("</html>\r\n", "utf8")) + 9:]
                            elif bytes("</html>\r\n", "utf8") not in encoded:
                                image_payload += bytes("", "utf8")
                            else:
                                pass

                        if not condition_a and not condition_b:
                            image_payload += encoded

                    http_payload += string_payload

            except:
                pass

        headers = get_http_headers(http_payload)

        if headers is None:
            continue



        image,image_type = extract_image(headers,image_payload)

        if (image is not None) and (image_type is not None) and ("gif" not in image_type) and "charset" not in image_type :
            #and (b"Content-Type" not in image or b"Content-Encoding" not in image):# and \


            file_name = "extractedImage-%d.%s" % (carved_images,image_type)
            #print(file_name)
            fd = open("%s/%s" % (pictures_directory,file_name),"wb")

            fd.write(image)
            fd.close()

            carved_images += 1

    print("\t\t[+] Image carving finished.")
    return carved_images

def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index("\\r\\n\\r\\n")+8]

        regex = r"(?<=\\n)([A-Z]{1}\w+\-\w+|[A-Z]{1}\w+)(?:\ *:\ *)(.*?)(?=\\r)"
        headers = dict(re.findall(regex, headers_raw))
    except:
        return None

    if "Content-Type" not in headers:
        return None

    return headers

def extract_image(headers,http_payload):
    image      = None
    image_type = None

    try:
        if "image" in headers['Content-Type']:
            image_type = headers['Content-Type'].split("/")[1]
            print(image_type)
            image = http_payload

            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None,None

    return image,image_type

def carver_input():
    print("             ############______Carve_Images_From_PCAP____############")

    try:
        if sys.version_info[0] < 3:
            pcap_file = raw_input("\t[>] PCAP File Location: \t\t")
            carver_path = raw_input("\t[>] Path to directory for extracted images: \t")
        else:
            pcap_file = input("\t[>] PCAP File Location: \t\t")
            carver_path = input("\t[>] Path to directory for extracted images: \t")
    except:
        pass

    if pcap_file is "": pcap_file = "/home/jo/Desktop/capture1.pcap"
    if carver_path is "": carver_path = "/root/PycharmProjects/MITM/carver"

    carved_images = http_assembler(pcap_file, carver_path)
    print("\t [+] Extracted: %d images to %s" % (carved_images, carver_path))

    menu.a_thing_that_makes_it_loop()

carver_input()