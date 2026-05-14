cp fc-ex/firecracker-v1.15.1-x86_64 fc-ex/firecracker
wget https://github.com/firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz

./setup1.sh
./start-firecracker.sh

./vm-list.sh

More info https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
