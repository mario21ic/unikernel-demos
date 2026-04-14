Instalar:
```
curl https://ops.city/get.sh -sSfL | sh
```

Ejecutar un bin con unikernel:
```
go build main.go
ops run <ejecutable>
ops run ./main

cd web/ && go build main.go
ops run main -p8080
curl localhost:8080
```

Deploy como instance:
```
ops deploy main -p8080
ops instance list
curl localhost:8080
```

Ejecutar un script con unikernel:
```
ops pkg load eyberg/node:20.5.0 -a hi.js
ops pkg load eyberg/python:3.10.6 -a main.py
```

Construir un unikernel
```
ops build <ejecutable>
ops build main
```

Muestra unikernels locales/remotos
```
ops image list
ops pkg list
```

Ejecuta un unikernel local con qemu:
```
qemu-system-x86_64 -nographic -drive file=/home/ubuntu/.ops/images/main,format=raw
```

Ejecuta un unikernel de Nanos:
```
ops pkg load eyberg/python3.10.6
```

More examples https://github.com/nanovms/ops-examples/
