#!/bin/bash

# The MAC address must be attached to the macvtap and be used inside the guest
mac="c2:67:4f:53:29:cb"
# Host network adapter to bridge the guest onto
host_net="ens18"

# Create the macvtap0 as a new virtual MAC associated with the host network
sudo ip link add link "$host_net" name macvtap0 type macvtap
sudo ip link set macvtap0 address "$mac" up
sudo ip link show macvtap0

# A new character device is created for this interface
tapindex=$(< /sys/class/net/macvtap0/ifindex)
tapdevice="/dev/tap$tapindex"

# Ensure that we can access this device
sudo chown "$UID:$UID" "$tapdevice"

# Use --net fd=3 to point to fd 3 which the shell has opened to point to the /dev/tapN device
#target/debug/cloud-hypervisor \
#	--kernel ~/src/linux/vmlinux \
#	--disk path=~/workloads/focal.raw \
#	--cpus boot=1 --memory size=512M \
#	--cmdline "root=/dev/vda1 console=hvc0" \
#    --net fd=3,mac=$mac 3<>"$tapdevice"

echo "Your tapdevice is "$tapdevice" with mac "$mac
