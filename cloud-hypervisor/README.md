Firmware booting:
```
wget https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img
qemu-img convert -p -f qcow2 -O raw focal-server-cloudimg-amd64.img focal-server-cloudimg-amd64.raw
wget https://github.com/cloud-hypervisor/rust-hypervisor-firmware/releases/download/0.4.2/hypervisor-fw
```

Create img, network and run VM:
```
./create-cloud-init.sh

./create-macvtap.sh

./run-demo.sh c2:67:4f:53:29:cb /dev/tap5
```

Note: user cloud and password cloud123. Don't forget to run on terminal: export TERM=xterm-256color

More info https://github.com/cloud-hypervisor/cloud-hypervisor
