#!/bin/bash
# run.sh — construye y lanza el container scratch vulnerable

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  PoC: App Vulnerable en FROM scratch             ║${NC}"
echo -e "${YELLOW}║  SOLO PARA FINES EDUCATIVOS                      ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
echo ""

ACTION="${1:-all}"

build() {
    echo -e "${GREEN}[*] Construyendo imagen FROM scratch...${NC}"
    #docker build -t vulnerable-scratch ./vulnerable-app/
    docker build -t vulnerable-scratch ./

    echo ""
    echo -e "${GREEN}[*] Tamaño de la imagen:${NC}"
    docker images vulnerable-scratch --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

    echo ""
    echo -e "${GREEN}[*] Verificando que el filesystem está vacío:${NC}"
    echo "Intentando listar el filesystem del container..."
    docker run --rm vulnerable-scratch ls / 2>&1 || \
        echo -e "${GREEN}  → 'ls' no existe — FROM scratch confirmado ✓${NC}"
}

run() {
    echo -e "${GREEN}[*] Deteniendo instancia previa si existe...${NC}"
    docker rm -f vulnerable-scratch-poc 2>/dev/null || true

    echo -e "${GREEN}[*] Lanzando container vulnerable...${NC}"
    docker run -d \
        --name vulnerable-scratch-poc \
        -p 8080:8080 \
        vulnerable-scratch

    echo ""
    echo -e "${GREEN}[+] Container corriendo:${NC}"
    docker ps --filter name=vulnerable-scratch-poc \
        --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

    echo ""
    echo -e "${GREEN}[+] Endpoints disponibles:${NC}"
    sleep 1
    curl -sf http://localhost:8080/info 2>/dev/null || \
        echo "  (esperando que arranque...)"

    echo ""
    echo -e "${YELLOW}Para ejecutar el exploit: ./attacker-payload/exploit.sh${NC}"
}

attack() {
    echo -e "${RED}[*] Ejecutando exploit...${NC}"
    bash ./exploit.sh http://localhost:8080
}

logs() {
    docker logs -f vulnerable-scratch-poc
}

stop() {
    docker rm -f vulnerable-scratch-poc 2>/dev/null || true
    echo "Container detenido."
}

case "$ACTION" in
    build)  build ;;
    run)    run ;;
    attack) attack ;;
    logs)   logs ;;
    stop)   stop ;;
    all)    build && run ;;
    *)
        echo "Uso: ./run.sh [build|run|attack|logs|stop|all]"
        echo ""
        echo "  build   → construir la imagen"
        echo "  run     → lanzar el container"
        echo "  attack  → ejecutar el exploit PoC"
        echo "  logs    → ver logs del container"
        echo "  stop    → detener el container"
        echo "  all     → build + run (default)"
        ;;
esac
