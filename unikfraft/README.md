Install:
```
curl -sSfL https://get.kraftkit.sh | sh
```

Pruebas:
```
kraft run unikraft.org/helloworld:latest
kraft run -p 8081:80 unikraft.org/nginx:1.25

curl localhost:8081

kraft pkg list
```

Probando un binario de c
```
gcc helloworld.c -o ./rootfs/helloworld
file rootfs/helloworld
ldd rootfs/helloworld

gcc -static-pie helloworld.c -o ./rootfs/helloworld
file rootfs/helloworld
ldd rootfs/helloworld

kraft build
kraft run
kraft run --rm --plat qemu --arch x86_64 .
```

Probando desde Docker:
```
docker run --runtime runu unikraft.org/app-nginx
```

More info 
* https://unikraft.org/docs/getting-started
* https://unikraft.org/docs/getting-started/integrations/container-runtimes

More examples https://github.com/unikraft/catalog/tree/main/examples
