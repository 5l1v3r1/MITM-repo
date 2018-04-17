#!/usr/bin/env bash

for nr in {1..255}
do
ping -c 1 -W 0.2 192.168.43.$nr > /dev/null & ## Possible error here if not on correct network when running

if ! (($nr % 51)); then
arp -a  >> /root/PycharmProjects/MITM/hosts2.txt
fi

done
exit 0