#!/bin/bash
set -xe

API_SOCKET="/tmp/firecracker.socket"
sudo rm -f $API_SOCKET
sudo ./fc-ex/firecracker --api-sock /tmp/firecracker.socket --enable-pci
