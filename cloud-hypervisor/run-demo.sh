#!/bin/bash
set -e

mac=$1
#tapdevice="/dev/tap5"
tapdevice=$2

echo "################"
echo "Hostname: cloud"
echo "User: cloud"
echo "Password: cloud123"
echo "Nota: don't forget to check the newtorking with dhclient & /etc/resolv.conf"
echo "################"

cloud-hypervisor      --firmware ./hypervisor-fw      --disk path=focal-server-cloudimg-amd64.raw path=./ubuntu-cloudinit.img         --cpus boot=4   --memory size=1024M --net fd=3,mac=$mac 3<>"$tapdevice"
