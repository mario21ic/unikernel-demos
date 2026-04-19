# PoC: FROM scratch no protege el kernel Linux

## Objetivo

Demostrar que un container `FROM scratch` **elimina herramientas del sistema
pero NO elimina la superficie del kernel Linux**. Un atacante con RCE en el
binario puede hacer syscalls directas sin necesitar bash, curl ni ninguna
herramienta.

## Estructura

```
scratch-poc/
├── vulnerable-app/
│   ├── main.go          ← App Go con vulnerabilidades intencionales
│   └── Dockerfile       ← FROM scratch — imagen mínima
├── attacker-payload/
│   └── exploit.sh       ← Script que demuestra el ataque
└── run.sh               ← Helper para build/run/attack
```

## Vulnerabilidades en la app

| Endpoint | Vulnerabilidad | Muestra |
|---|---|---|
| `/ping?host=` | Command injection | Shell no disponible en scratch |
| `/read?path=` | Path traversal | /proc sí accesible |
| `/syscalls` | - | Syscalls directas sin herramientas |
| `/procinfo` | - | Info del kernel HOST via /proc |

## Cómo ejecutar

```bash
# 1. Construir y lanzar
chmod +x run.sh attacker-payload/exploit.sh
./run.sh build
./run.sh run

# 2. Ver los endpoints manualmente
curl http://localhost:8080/info
curl http://localhost:8080/syscalls
curl http://localhost:8080/procinfo

# 3. Ejecutar el exploit completo
./run.sh attack

# 4. Limpiar
./run.sh stop
```

## Lo que demuestra cada fase

### Fase 1 — scratch SÍ protege contra:
- `bash -c "id"` → no hay bash
- `/etc/passwd` → no existe en scratch
- Herramientas del sistema

### Fase 2 — scratch NO protege contra syscalls:
```
SYS_GETUID   → UID=0 (root sin USER declarado)
SYS_UNAME    → versión del kernel HOST → buscar CVEs
SYS_SOCKET   → crear sockets TCP sin curl ni nc
SYS_MMAP     → mapear memoria ejecutable (shellcode)
```

### Fase 3 — /proc expone el HOST:
```
/proc/version          → versión exacta del kernel
/proc/net/tcp          → sockets del HOST
/proc/net/arp          → otros hosts en la red
/proc/1/environ        → secrets del proceso init
/proc/self/maps        → layout de memoria (bypass ASLR)
```

## Mitigaciones reales

### Nivel 1 — seccomp (bloquear syscalls peligrosas)
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names": ["read","write","accept","connect"], "action": "SCMP_ACT_ALLOW"}
  ]
}
```
```bash
docker run --security-opt seccomp=seccomp-profile.json vulnerable-scratch
```

### Nivel 2 — no root (USER en Dockerfile)
```dockerfile
FROM scratch
COPY --from=builder /app/vulnerable-app /vulnerable-app
USER 65534:65534    # nobody:nogroup
```

### Nivel 3 — read-only filesystem + no /proc
```bash
docker run \
  --read-only \
  --tmpfs /tmp \
  --security-opt no-new-privileges \
  vulnerable-scratch
```

### Nivel 4 — Firecracker (aislamiento hardware)
```
Container scratch + Firecracker MicroVM
→ El kernel Linux del guest está aislado del host por KVM
→ Breakout requiere CVE en el hypervisor (mucho más raro)
```

### Nivel 5 — Unikernel Nanos (eliminar Linux del guest)
```
No hay kernel Linux en el guest
→ /proc no existe
→ SYS_PTRACE no implementado → ENOSYS
→ SYS_FORK no existe
→ CVEs de Linux no aplican al guest
→ Superficie: ~50 syscalls vs ~400 en Linux
```

## Tabla de protección por técnica

| Técnica | Shell | /proc | Syscalls | CVEs kernel | Breakout |
|---|---|---|---|---|---|
| FROM scratch | ❌ | ✅ expuesto | ✅ expuestas | ✅ aplican | Posible |
| + seccomp | ❌ | ⚠️ parcial | ⚠️ filtradas | ✅ aplican | Difícil |
| + Firecracker | ❌ | ⚠️ guest | ⚠️ guest | ⚠️ guest | Muy difícil |
| Unikernel | ❌ | ❌ no existe | ❌ solo ~50 | ❌ no aplican | Extremo |
