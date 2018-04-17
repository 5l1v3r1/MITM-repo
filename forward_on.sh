#!/bin/sh
# comment

#sudo su

echo 1 > /proc/sys/net/ipv4/ip_forward
echo "[+] IP forwarding set to: 1"
exit 0
