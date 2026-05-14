#!/bin/bash

echo "=== Firecracker VMs activas ==="
for sock in /tmp/firecracker-*.socket; do
    vm=$(basename $sock .socket | sed 's/firecracker-//')
    pid=$(pgrep -f "api-sock $sock" 2>/dev/null || echo "muerto")
    ip="172.16.$(echo $vm | grep -oE '[0-9]+$').2"
    echo "  $vm | PID: $pid | IP: $ip | screen -r $vm"
done
echo ""
sudo screen -ls
