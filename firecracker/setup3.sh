#!/bin/bash
set -xe

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
TAP_DEV="tap0"
TAP_IP="172.16.0.1"
MASK_SHORT="/30"

# Setup network interface
sudo ip link del "$TAP_DEV" 2>/dev/null || true
sudo ip tuntap add dev "$TAP_DEV" mode tap
sudo ip addr add "${TAP_IP}${MASK_SHORT}" dev "$TAP_DEV"
sudo ip link set dev "$TAP_DEV" up

# Enable ip forwarding
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -P FORWARD ACCEPT

HOST_IFACE=$(ip -j route list default | jq -r '.[0].dev')
sudo iptables -t nat -D POSTROUTING -o "$HOST_IFACE" -j MASQUERADE || true
sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE

# Generar config file con paths absolutos
cat > "${WORKDIR}/vm-config.json" << EOF
{
  "boot-source": {
    "kernel_image_path": "${WORKDIR}/$(ls ${WORKDIR}/vmlinux* | xargs basename)",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  },
  "machine-config": {
    "vcpu_count": 2,
    "mem_size_mib": 2048,
    "smt": false
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "${WORKDIR}/$(ls ${WORKDIR}/*.ext4 | xargs basename)",
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
    "log_path": "${WORKDIR}/firecracker.log",
    "level": "Debug",
    "show_level": true,
    "show_log_origin": true
  }
}
EOF

# Lanzar Firecracker
API_SOCKET="/tmp/firecracker.socket"
sudo rm -f $API_SOCKET
sudo screen -S microvm1 -dm bash -c \
    "sudo ./fc-ex/firecracker \
        --api-sock ${API_SOCKET} \
        --config-file '${WORKDIR}/vm-config.json'"

echo "
# Ver que la sesión existe
screen -ls

# Adjuntarte para ver el output de la VM (consola serie)
screen -r microvm1

# Detacharte sin matar la VM (dentro de screen)
Ctrl+A  D

# Mandar un comando a la sesión sin entrar
screen -S microvm1 -X stuff "ip addr\n"

# Matar la sesión (apaga la VM)
screen -S microvm1 -X quit
"

FC_PID=$!
echo "### FC_PID: "$FC_PID

# Esperar a que la VM arranque y SSH esté disponible
echo "Esperando que la microVM arranque..."
sleep 4s

KEY_NAME=./$(ls *.id_rsa | tail -1)

# Setup internet access in the guest
VM_IP="172.16.0.2"

#ssh -i $KEY_NAME root@$VM_IP  "ip route add default via ${TAP_IP} dev eth0"
sudo screen -S microvm1 -p 0 -X stuff "ip route add default via ${TAP_IP} dev eth0\n"

# Setup DNS resolution in the guest
#ssh -i $KEY_NAME root@$VM_IP  "echo 'nameserver 8.8.8.8' > /etc/resolv.conf"
sudo screen -S microvm1 -p 0 -X stuff "echo 'nameserver 8.8.8.8' > /etc/resolv.conf\n"

# Setup hostname
HOSTNAME_VM="microvm1"
#ssh -i $KEY_NAME root@$VM_IP  "hostnamectl set-hostname $HOSTNAME_VM"
#ssh -i $KEY_NAME root@$VM_IP  "echo '127.0.0.1	$HOSTNAME_VM' >> /etc/hosts"
#sudo screen -S microvm1 -p 0 -X stuff "hostnamectl set-hostname ${HOSTNAME_VM}\n"
sudo screen -S microvm1 -p 0 -X stuff "hostname ${HOSTNAME_VM}\n"
sudo screen -S microvm1 -p 0 -X stuff "echo '127.0.0.1    ${HOSTNAME_VM}' >> /etc/hosts\n"

# SSH into the microVM
#ssh -i $KEY_NAME root@$VM_IP
sudo screen -r microvm1
