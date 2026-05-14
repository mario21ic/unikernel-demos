#!/bin/bash
set -xe

sudo pkill firecracker
sudo rm -f /tmp/firecracker-nanos.socket
