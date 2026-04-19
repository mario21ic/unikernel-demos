package main

// PoC: App vulnerable corriendo en FROM scratch
// Vulnerabilidad: Server-Side Template Injection → RCE
// Propósito educativo: demostrar que scratch no protege el kernel

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// Vulnerabilidad 1: Command Injection
// El endpoint /ping ejecuta un comando del sistema con input del usuario
// SIN sanitizació vulnerabilidad clásica
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		fmt.Fprintln(w, "Uso: /ping?host=<ip>")
		return
	}

	// VULNERABLE: input del usuario directo en exec.Command
	// Un atacante puede pasar: ?host=;id o ?host=;cat /etc/passwd
	// Pero en scratch... no hay /bin/sh ni /etc/passwd
	// ¿Realmente estamos seguros?
	cmd := exec.Command("sh", "-c", "ping -c1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// En scratch no hay sh — el error lo revela
		fmt.Fprintf(w, "Error: %v\nOutput: %s\n", err, out)
		fmt.Fprintln(w, "\n[!] No hay shell en scratch — pero hay syscalls...")
		return
	}
	fmt.Fprintf(w, "%s", out)
}

// Vulnerabilidad 2: Arbitrary File Read
// Simula una vulnerabilidad de path traversal
// En scratch no hay /etc/passwd... pero hay /proc
func readFileHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		fmt.Fprintln(w, "Uso: /read?path=<ruta>")
		return
	}

	// VULNERABLE: lee cualquier archivo del sistema
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "Error: %v\n", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", data)
}

// Demostración: Syscall directa SIN herramienta
// Esto simula lo que un atacante haría con RCE en un binario Go
// No necesita bash, curl, ni NINGUNA herramienta del sistema
// Las syscalls son instrucciones de CPU, no comandos de OS
func syscallDemoHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "=== Demostración: Syscalls directas desde scratch ===\n")

	// 1. SYS_GETPID obtener PID propio 
	pid, _, _ := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	fmt.Fprintf(w, "[syscall SYS_GETPID]\n  PID: %d\n\n", pid)

	// 2. SYS_GETUID obtener UID (¿corremos como root?)
	uid, _, _ := syscall.RawSyscall(syscall.SYS_GETUID, 0, 0, 0)
	gid, _, _ := syscall.RawSyscall(syscall.SYS_GETGID, 0, 0, 0)
	fmt.Fprintf(w, "[syscall SYS_GETUID / SYS_GETGID]\n  UID: %d  GID: %d\n", uid, gid)
	if uid == 0 {
		fmt.Fprintln(w, "  [!] CORREMOS COMO ROOT  escalada trivial")
	} else {
		fmt.Fprintln(w, "  [!] NO CORREMOS COMO ROOT definieron USER")
        }
	fmt.Fprintln(w)

	// 3. SYS_UNAME info del kernel del HOST
	// Esto revela la versión del kernel Linux del HOST
	// Con esta info un atacante busca CVEs específicos
	var uname syscall.Utsname
	syscall.Uname(&uname)
	sysname := charsToString(uname.Sysname[:])
	release := charsToString(uname.Release[:])
	machine := charsToString(uname.Machine[:])
	fmt.Fprintf(w, "[syscall SYS_UNAME — kernel del HOST]\n")
	fmt.Fprintf(w, "  OS      : %s\n", sysname)
	fmt.Fprintf(w, "  Kernel  : %s\n", release)
	fmt.Fprintf(w, "  Arch    : %s\n", machine)
	fmt.Fprintf(w, "  [!] Con esta versión busco CVEs en https://cve.mitre.org\n\n")

	// 4. SYS_OPEN + SYS_READ leer /proc/self/maps
	// /proc existe aunque scratch no tenga archivos propios
	// Revela el layout de memoria — útil para bypass de ASLR
	maps, err := os.ReadFile("/proc/self/maps")
	if err == nil {
		lines := strings.Split(string(maps), "\n")
		fmt.Fprintf(w, "[/proc/self/maps — layout de memoria del proceso]\n")
		for i, line := range lines {
			if i >= 8 {
				fmt.Fprintf(w, "  ... (%d líneas más)\n", len(lines)-8)
				break
			}
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}

	// 5. SYS_OPEN + SYS_READ  leer /proc/net/tcp
	// Revela todos los sockets TCP abiertos en el HOST
	// Incluyendo servicios que no están expuestos externamente
	netTCP, err := os.ReadFile("/proc/net/tcp")
	if err == nil {
		lines := strings.Split(string(netTCP), "\n")
		fmt.Fprintf(w, "[/proc/net/tcp — sockets TCP del HOST]\n")
		for i, line := range lines {
			if i >= 6 {
				fmt.Fprintf(w, "  ... (%d entradas más)\n", len(lines)-6)
				break
			}
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}

	// 6. SYS_OPEN + SYS/READ  /proc/1/environ 
	// PID 1 es el proceso init del host (o del namespace)
	// Puede exponer variables de entorno con secrets
	environ, err := os.ReadFile("/proc/1/environ")
	if err == nil {
		vars := strings.Split(string(environ), "\x00")
		fmt.Fprintf(w, "[/proc/1/environ — env vars del proceso init]\n")
		for i, v := range vars {
			if i >= 10 || v == "" {
				break
			}
			// Resaltar posibles secrets
			upper := strings.ToUpper(v)
			if containsAny(upper, []string{"TOKEN", "SECRET", "KEY", "PASS", "API"}) {
				fmt.Fprintf(w, "  [SECRET!] %s\n", v)
			} else {
				fmt.Fprintf(w, "  %s\n", v)
			}
		}
		fmt.Fprintln(w)
	}

	// 7. SYS_SOCKET  crear socket raw SIN herramientas 
	// Un atacante puede establecer una reverse shell
	// usando solo syscalls — sin bash, sin nc, sin curl
	fmt.Fprintf(w, "[SYS_SOCKET — crear socket de red sin herramientas]\n")
	fd, _, errno := syscall.RawSyscall(
		syscall.SYS_SOCKET,
		syscall.AF_INET,
		syscall.SOCK_STREAM,
		0,
	)
	if errno == 0 {
		fmt.Fprintf(w, "  Socket TCP creado: fd=%d\n", fd)
		fmt.Fprintf(w, "  [!] Podría conectarme a un C2 server sin bash ni curl\n")
		syscall.Close(int(fd))
	}
	fmt.Fprintln(w)

	// 8. SYS_MMAP  mapear memoria ejecutable 
	// Prerrequisito para shellcode injection
	// Disponible en kernel Linux aunque scratch esté "vacío"
	fmt.Fprintf(w, "[SYS_MMAP — memoria ejecutable]\n")
	mem, _, errno := syscall.RawSyscall6(
		syscall.SYS_MMAP,
		0,
		4096,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
		^uintptr(0),
		0,
	)
	if errno == 0 {
		fmt.Fprintf(w, "  Memoria RWX mapeada en: 0x%x\n", mem)
		fmt.Fprintf(w, "  [!] Podría escribir y ejecutar shellcode arbitrario\n")
		// Demostramos que es ejecutable escribiendo un NOP y saltando
		nopSlide := (*[1]byte)(unsafe.Pointer(mem))
		nopSlide[0] = 0x90 // NOP instruction
		syscall.RawSyscall(syscall.SYS_MUNMAP, mem, 4096, 0)
		fmt.Fprintf(w, "  Memoria liberada.\n")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "=== Resumen ===\n")
	fmt.Fprintf(w, "FROM scratch eliminó: bash, curl, wget, tools\n")
	fmt.Fprintf(w, "FROM scratch NO eliminó: syscalls del kernel Linux\n")
	fmt.Fprintf(w, "Runtime: %s/%s — Go no necesita nada externo\n",
		runtime.GOOS, runtime.GOARCH)
}

// Info del entorno
func infoHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "=== Info del entorno (desde scratch) ===")
	fmt.Fprintf(w, "Hostname   : %s\n", getHostname())
	fmt.Fprintf(w, "PID        : %d\n", os.Getpid())
	fmt.Fprintf(w, "UID/GID    : %d/%d\n", os.Getuid(), os.Getgid())
	fmt.Fprintf(w, "Go version : %s\n", runtime.Version())
	fmt.Fprintf(w, "GOOS/ARCH  : %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	fmt.Fprintln(w, "=== Endpoints disponibles ===")
	fmt.Fprintln(w, "  /info      — este menú")
	fmt.Fprintln(w, "  /ping      — command injection demo  (?host=<ip>)")
	fmt.Fprintln(w, "  /read      — path traversal demo     (?path=<ruta>)")
	fmt.Fprintln(w, "  /syscalls  — syscall directa demo")
	fmt.Fprintln(w, "  /procinfo  — lectura de /proc/*")
}

// Leer /proc en detalle
func procinfoHandler(w http.ResponseWriter, r *http.Request) {
	files := []string{
		"/proc/version",       // versión exacta del kernel host
		"/proc/cpuinfo",       // info del CPU
		"/proc/meminfo",       // memoria total del host
		"/proc/net/arp",       // tabla ARP — otros hosts en la red
		"/proc/net/route",     // tabla de rutas del host
		"/proc/self/cgroup",   // cgroup del container
		"/proc/self/status",   // estado del proceso
	}

	fmt.Fprintln(w, "=== Lectura de /proc desde container scratch ===\n")
	fmt.Fprintln(w, "[!] /proc expone información del kernel HOST, no del container\n")

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(w, "── %s ──\n  (no accesible: %v)\n\n", f, err)
			continue
		}
		content := string(data)
		if len(content) > 300 {
			content = content[:300] + "\n  ...(truncado)"
		}
		fmt.Fprintf(w, "── %s ──\n%s\n\n", f, content)
	}
}

// Helpers
func charsToString(ca []int8) string {
	s := make([]byte, len(ca))
	for i, c := range ca {
		if c == 0 {
			return string(s[:i])
		}
		s[i] = byte(c)
	}
	return string(s)
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func main() {
	http.HandleFunc("/", infoHandler)
	http.HandleFunc("/info", infoHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/read", readFileHandler)
	http.HandleFunc("/syscalls", syscallDemoHandler)
	http.HandleFunc("/procinfo", procinfoHandler)

	port := ":8080"
	log.Printf("[vulnerable-app] Corriendo en %s (FROM scratch)", port)
	log.Printf("[vulnerable-app] Visita /info para ver los endpoints")
	log.Fatal(http.ListenAndServe(port, nil))
}
