#!/bin/bash
#set -xe
set -e

# ─────────────────────────────────────────────
# USO: ./setup4.sh <vm-name> [vcpus] [mem_mib]
# EJEMPLO: ./setup4.sh microvm1
#          ./setup4.sh microvm2 4 4096
# ─────────────────────────────────────────────

VM_NAME="${1:?Error: debes pasar un nombre de VM. Ej: ./setup4.sh microvm1}"
VCPUS="${2:-2}"
MEM_MIB="${3:-2048}"

WORKDIR="$(cd "$(dirname "$0")" && pwd)"

# ─────────────────────────────────────────────
# Derivar recursos únicos por VM desde el nombre
# microvm1 → índice 1, microvm2 → índice 2, etc.
# ─────────────────────────────────────────────
VM_INDEX=$(echo "$VM_NAME" | grep -oE '[0-9]+$')
if [ -z "$VM_INDEX" ]; then
    echo "Error: el nombre debe terminar en número. Ej: microvm1, microvm2"
    exit 1
fi

# Cada VM ocupa un /30 en 172.16.X.0/30
# VM1 → tap0  172.16.1.1/30  guest: 172.16.1.2
# VM2 → tap1  172.16.2.1/30  guest: 172.16.2.2
# VM3 → tap2  172.16.3.1/30  guest: 172.16.3.2
TAP_DEV="tap${VM_INDEX}"
TAP_IP="172.16.${VM_INDEX}.1"
VM_IP="172.16.${VM_INDEX}.2"
MASK_SHORT="/30"

# MAC única por VM: último octeto = VM_INDEX
# 06:00:AC:10:00:01, 06:00:AC:10:00:02, ...
#MAC_SUFFIX=$(printf '%02X' "$VM_INDEX")
#FC_MAC="06:00:AC:10:00:${MAC_SUFFIX}"
# fix para 172.16.x.2
MAC_INDEX=$(printf '%02X' "$VM_INDEX")
FC_MAC="06:00:AC:10:${MAC_INDEX}:02"

# Socket y log únicos por VM
API_SOCKET="/tmp/firecracker-${VM_NAME}.socket"
LOGFILE="${WORKDIR}/${VM_NAME}.log"

# Directorio de trabajo aislado por VM
VM_DIR="${WORKDIR}/vms/${VM_NAME}"
mkdir -p "$VM_DIR"

# ─────────────────────────────────────────────
# Rootfs: clonar el base o reusar si ya existe
# ─────────────────────────────────────────────
BASE_ROOTFS="${WORKDIR}/$(ls ${WORKDIR}/*.ext4 | head -1 | xargs basename)"
VM_ROOTFS="${VM_DIR}/rootfs.ext4"

if [ ! -f "$VM_ROOTFS" ]; then
    echo "Clonando rootfs base para ${VM_NAME}..."
    cp "$BASE_ROOTFS" "$VM_ROOTFS"
else
    echo "Reutilizando rootfs existente: $VM_ROOTFS"
fi

KERNEL="${WORKDIR}/$(ls ${WORKDIR}/vmlinux* | xargs basename)"
KEY_NAME="${WORKDIR}/$(ls ${WORKDIR}/*.id_rsa | xargs basename)"

# ─────────────────────────────────────────────
# Red
# ─────────────────────────────────────────────
sudo ip link del "$TAP_DEV" 2>/dev/null || true
sudo ip tuntap add dev "$TAP_DEV" mode tap
sudo ip addr add "${TAP_IP}${MASK_SHORT}" dev "$TAP_DEV"
sudo ip link set dev "$TAP_DEV" up

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo iptables -P FORWARD ACCEPT

HOST_IFACE=$(ip -j route list default | jq -r '.[0].dev')
sudo iptables -t nat -D POSTROUTING -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null || true
sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE

# ─────────────────────────────────────────────
# Generar vm-config.json por VM
# ─────────────────────────────────────────────
CONFIG_JSON="${VM_NAME}-vm-config.json"
cat > "${VM_DIR}/${CONFIG_JSON}" << EOF
{
  "boot-source": {
    "kernel_image_path": "${KERNEL}",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  },
  "machine-config": {
    "vcpu_count": ${VCPUS},
    "mem_size_mib": ${MEM_MIB},
    "smt": false
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "${VM_ROOTFS}",
      "is_root_device": true,
      "is_read_only": false,
      "cache_type": "Unsafe",
      "io_engine": "Sync"
    }
  ],
  "network-interfaces": [
    {
      "iface_id": "net1",
      "guest_mac": "${FC_MAC}",
      "host_dev_name": "${TAP_DEV}"
    }
  ],
  "logger": {
    "log_path": "${LOGFILE}",
    "level": "Debug",
    "show_level": true,
    "show_log_origin": true
  }
}
EOF

echo "=== Config generada para ${VM_NAME} ==="
echo "  TAP     : ${TAP_DEV} → ${TAP_IP}"
echo "  VM IP   : ${VM_IP}"
echo "  MAC     : ${FC_MAC}"
echo "  vCPUs   : ${VCPUS}"
echo "  RAM     : ${MEM_MIB} MiB"
echo "  Rootfs  : ${VM_ROOTFS}"
echo "  Socket  : ${API_SOCKET}"
echo "  Log     : ${LOGFILE}"
echo ""

# ─────────────────────────────────────────────
# Verificar que no haya una sesión screen con ese nombre ya
# ─────────────────────────────────────────────
if sudo screen -ls | grep -q "${VM_NAME}"; then
    echo "Error: ya existe una sesión screen llamada '${VM_NAME}'"
    echo "Para matarla: screen -S ${VM_NAME} -X quit"
    exit 1
fi

# ─────────────────────────────────────────────
# Lanzar Firecracker en screen
# ─────────────────────────────────────────────
sudo rm -f "$API_SOCKET"
sudo screen -S "$VM_NAME" -dm bash -c \
    "sudo ${WORKDIR}/fc-ex/firecracker \
        --api-sock ${API_SOCKET} \
        --config-file '${VM_DIR}/${CONFIG_JSON}' \
    2>&1 | tee ${VM_DIR}/console.log"

echo "Esperando que ${VM_NAME} arranque..."
sleep 5s

# ─────────────────────────────────────────────
# Configurar red dentro de la VM vía screen
# ─────────────────────────────────────────────
sudo screen -S "$VM_NAME" -p 0 -X stuff "ip route add default via ${TAP_IP} dev eth0\n"
sleep 0.5s
sudo screen -S "$VM_NAME" -p 0 -X stuff "echo 'nameserver 8.8.8.8' > /etc/resolv.conf\n"
sleep 0.5s
#sudo screen -S "$VM_NAME" -p 0 -X stuff "hostnamectl set-hostname ${VM_NAME}\n"
#sudo screen -S "$VM_NAME" -p 0 -X stuff "hostname ${VM_NAME}\n"
sudo screen -S "$VM_NAME" -p 0 -X stuff "echo '${VM_NAME}' > /etc/hostname && hostname -F /etc/hostname\n"
sleep 0.5s
sudo screen -S "$VM_NAME" -p 0 -X stuff "echo '127.0.0.1 ${VM_NAME}' >> /etc/hosts\n"
sleep 0.5s
sudo screen -S "$VM_NAME" -p 0 -X stuff "export TERM=xterm\n"

echo ""
echo "=== ${VM_NAME} corriendo ==="
echo "  screen -r ${VM_NAME}           # ver consola"
echo "  ssh -i ${KEY_NAME} root@${VM_IP}  # SSH directo"
echo "  screen -S ${VM_NAME} -X quit   # apagar"
echo ""

# Adjuntar la consola
#sudo screen -r "$VM_NAME"
#ssh -i ${KEY_NAME} root@${VM_IP}
