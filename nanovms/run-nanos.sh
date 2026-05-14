#!/bin/bash
set -xe

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
FC_BIN="${WORKDIR}/../firecracker/fc-ex/firecracker"

TAP_DEV="tap0"
TAP_IP="172.16.0.1"
VM_IP="172.16.0.2"
VM_GW="172.16.0.1"
VM_MASK="255.255.255.252"
MASK_SHORT="/30"
API_SOCKET="/tmp/firecracker-nanos.socket"
HOST_IFACE=$(ip -j route list default | jq -r '.[0].dev')

# ─── Cleanup forzado de cualquier proceso previo ──────
echo "=== Limpiando recursos previos ==="

# Matar cualquier firecracker que tenga tap0 abierto
for pid in $(sudo lsof /dev/net/tun 2>/dev/null | grep firecracker | awk '{print $2}'); do
    echo "Matando firecracker PID $pid que tenía tap0..."
    sudo kill -9 "$pid" 2>/dev/null || true
done
sleep 0.5s

# Destruir y recrear tap limpiamente
sudo ip link set "$TAP_DEV" down 2>/dev/null || true
sudo ip link del "$TAP_DEV" 2>/dev/null || true
sudo rm -f "$API_SOCKET"
sudo rm -f /tmp/nanos-fc.log
sleep 0.3s

# ─── Crear tap con vnet_hdr explícito ─────────────────
# multi_queue desactivado (Nanos/Firecracker no lo soportan)
sudo ip tuntap add dev "$TAP_DEV" mode tap
sudo ip link set dev "$TAP_DEV" mtu 1500
sudo ip addr add "${TAP_IP}${MASK_SHORT}" dev "$TAP_DEV"
sudo ip link set dev "$TAP_DEV" up

# Verificar que está UP
ip link show "$TAP_DEV" | grep -i ",UP" || {
    echo "ERROR: tap0 no está configurado"
    exit 1
}

# ─── NAT ──────────────────────────────────────────────
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -P FORWARD ACCEPT
sudo iptables -t nat -D POSTROUTING -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null || true
sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE

echo "=== Red OK: ${TAP_IP} → ${VM_IP} ==="

# ─── Config ───────────────────────────────────────────
cat > "${WORKDIR}/vm-config.json" << EOF
{
  "boot-source": {
    "kernel_image_path": "/home/ubuntu/.ops/0.1.54/kernel.img",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  },
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 512,
    "smt": false
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "/home/ubuntu/.ops/images/main",
      "is_root_device": true,
      "is_read_only": false
    }
  ],
  "network-interfaces": [
    {
      "iface_id": "net1",
      "guest_mac": "06:00:AC:10:00:02",
      "host_dev_name": "${TAP_DEV}"
    }
  ],
  "logger": {
    "log_path": "/tmp/nanos-fc.log",
    "level": "Debug",
    "show_level": true,
    "show_log_origin": true
  }
}
EOF

# ─── Lanzar ───────────────────────────────────────────
echo "=== Lanzando unikernel Nanos ==="
echo "    VM IP  : ${VM_IP}"
echo "    Log    : tail -f /tmp/nanos-fc.log"
echo ""

sudo "$FC_BIN" \
    --api-sock "$API_SOCKET" \
    --config-file "${WORKDIR}/vm-config.json"
