#!/bin/bash
set -xe

sudo rm -f /tmp/firecracker.socket
sudo ../firecracker/fc-ex/firecracker --api-sock /tmp/firecracker.socket     --config-file vm-config.json
