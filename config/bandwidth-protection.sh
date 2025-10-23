#!/bin/bash
#
# bandwidth-protection-improved.sh - Sistema de protección mejorado para usuarios reales
# Versión: 3.0
# Requiere: iptables, ipset, tc (iproute2)
#

set -euo pipefail

# ==================== CONFIGURACIÓN ====================

# Directorios y archivos
readonly LOG_DIR="/var/log/bandwidth-protection"
readonly STATE_DIR="/var/lib/bandwidth-protection"
readonly BLOCKLIST_FILE="${STATE_DIR}/blocked_ips.txt"
readonly WHITELIST_FILE="${STATE_DIR}/whitelist_ips.txt"
readonly TRUSTED_FILE="${STATE_DIR}/trusted_ips.txt"  # IPs de administradores
readonly LOG_FILE="${LOG_DIR}/protection.log"

# Parámetros de red
readonly INTERFACE="${INTERFACE:-eth0}"

# ==================== LÍMITES PARA USUARIOS NORMALES ====================
# Estos límites son generosos para usuarios reales pero restrictivos para bots

# Límites de conexiones HTTP/HTTPS (usuarios reales navegan)
readonly MAX_HTTP_CONN_PER_IP=100              # Conexiones HTTP simultáneas
readonly MAX_HTTP_REQUESTS=300                 # Requests por minuto (5 por segundo)
readonly HTTP_BURST=50                         # Burst inicial permitido

# Límites de conexiones generales
readonly MAX_CONN_PER_IP=150                   # Total conexiones simultáneas
readonly MAX_NEW_CONN_RATE=40                  # Nuevas conexiones por segundo

# ==================== LÍMITES PARA SSH (TU CASO) ====================
# SSH necesita límites muy permisivos ya que mantienes sesiones largas

readonly SSH_PORT=22
readonly MAX_SSH_ATTEMPTS=10                   # Intentos de login por minuto
readonly MAX_SSH_CONN_PER_IP=10                # Sesiones SSH simultáneas
readonly SSH_ESTABLISHED_UNLIMITED=1           # No limitar SSH establecido

# ==================== LÍMITES PARA TRANSFERENCIA DE ARCHIVOS ====================
# Para rsync, scp, sftp, git push, etc.

readonly MAX_UPLOAD_CONNECTIONS=20             # Conexiones para subir archivos
readonly FILE_TRANSFER_BANDWIDTH="200mbit"      # Ancho de banda para transferencias

# ==================== PROTECCIÓN ICMP (PING) ====================
# Tu ping cada 30s no será afectado

readonly ICMP_LIMIT=10                         # 10 pings por segundo es muy permisivo
readonly ICMP_BURST=20                         # Burst para pings legítimos

# ==================== LÍMITES AGRESIVOS PARA BOTS ====================

readonly SYN_FLOOD_LIMIT=20                    # SYN packets por segundo
readonly UDP_FLOOD_LIMIT=100                   # UDP packets por segundo
readonly INVALID_PACKET_LIMIT=10               # Paquetes inválidos por segundo

# Ancho de banda
readonly MAX_BANDWIDTH_PER_IP="100mbit"         # Por IP normal
readonly TRUSTED_BANDWIDTH="800mbit"           # Para IPs confiables (tú)
readonly GLOBAL_MAX_BANDWIDTH="900mbit"

# Puertos a proteger
readonly HTTP_PORT=80
readonly HTTPS_PORT=443

# Tiempo de bloqueo (más corto para evitar bloqueos accidentales)
readonly BLOCK_TIME=1800                       # 30 minutos

# ==================== DETECCIÓN INTELIGENTE ====================

# Un bot típico:
# - Hace muchas conexiones diferentes en poco tiempo
# - No mantiene conexiones establecidas por mucho tiempo
# - Ignora respuestas y solo envía requests
# - No tiene comportamiento interactivo

readonly BOT_DETECTION_WINDOW=60               # Ventana de análisis (segundos)
readonly BOT_NEW_CONN_THRESHOLD=100            # Nuevas conexiones en ventana
readonly BOT_SHORT_CONN_RATIO=0.8              # 80% de conexiones duran <5s

# ==================== FUNCIONES AUXILIARES ====================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Este script debe ejecutarse como root"
        exit 1
    fi
}

check_dependencies() {
    local deps=("iptables" "ipset" "tc" "awk" "grep" "netstat")
    local missing=()

    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Dependencias faltantes: ${missing[*]}"
        error "Instala con: apt-get install iptables ipset iproute2 net-tools"
        exit 1
    fi
}

setup_directories() {
    mkdir -p "$LOG_DIR" "$STATE_DIR"
    touch "$BLOCKLIST_FILE" "$WHITELIST_FILE" "$TRUSTED_FILE"
    chmod 600 "$BLOCKLIST_FILE" "$WHITELIST_FILE" "$TRUSTED_FILE"
}

# ==================== GESTIÓN DE IPSET ====================

create_ipsets() {
    log "Creando conjuntos de IPs..."

    # IPs de confianza total (administradores, tu IP)
    ipset create -exist trusted_ips hash:ip maxelem 100

    # IPs en whitelist automática (usuarios que pasan validación)
    ipset create -exist whitelist_ips hash:ip timeout 86400 maxelem 10000  # 24 horas

    # IPs bloqueadas temporalmente
    ipset create -exist blocked_ips hash:ip timeout "$BLOCK_TIME" maxelem 65536

    # IPs sospechosas en observación
    ipset create -exist suspicious_ips hash:ip timeout 300 maxelem 65536  # 5 minutos

    # Rate limiting sets
    ipset create -exist http_recent hash:ip timeout 60 maxelem 100000
    ipset create -exist ssh_recent hash:ip timeout 60 maxelem 10000

    # Cargar IPs de confianza
    if [[ -s "$TRUSTED_FILE" ]]; then
        while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ipset add -exist trusted_ips "$ip"
        done < "$TRUSTED_FILE"
        log "Cargadas $(ipset list trusted_ips | grep -c 'Members:' || echo 0) IPs de confianza"
    fi

    # Cargar whitelist persistente
    if [[ -s "$WHITELIST_FILE" ]]; then
        while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ipset add -exist whitelist_ips "$ip" timeout 0
        done < "$WHITELIST_FILE"
    fi

    log "Conjuntos de IPs creados correctamente"
}

# ==================== REGLAS DE IPTABLES ====================

setup_iptables() {
    log "Configurando reglas de iptables..."

    # Crear cadenas personalizadas
    iptables -N RATE_LIMIT 2>/dev/null || iptables -F RATE_LIMIT
    iptables -N DDOS_PROTECT 2>/dev/null || iptables -F DDOS_PROTECT
    iptables -N HTTP_PROTECT 2>/dev/null || iptables -F HTTP_PROTECT
    iptables -N SSH_PROTECT 2>/dev/null || iptables -F SSH_PROTECT
    iptables -N BOT_DETECT 2>/dev/null || iptables -F BOT_DETECT

    # ========== PRIORIDAD 1: IPs DE CONFIANZA (TÚ) ==========
    # Las IPs de confianza tienen acceso ilimitado

    iptables -A INPUT -m set --match-set trusted_ips src -j ACCEPT
    iptables -A OUTPUT -m set --match-set trusted_ips dst -j ACCEPT
    iptables -A FORWARD -m set --match-set trusted_ips src -j ACCEPT

    log "IPs de confianza tienen acceso sin restricciones"

    # ========== PRIORIDAD 2: TRÁFICO ESTABLECIDO ==========
    # Permitir conexiones ya establecidas (incluyendo tu SSH activo)

    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # ========== PRIORIDAD 3: BLOQUEOS ACTIVOS ==========

    iptables -A INPUT -m set --match-set blocked_ips src -j DROP

    # ========== PRIORIDAD 4: WHITELIST AUTOMÁTICA ==========
    # IPs que han demostrado ser usuarios reales

    iptables -A INPUT -m set --match-set whitelist_ips src -j ACCEPT

    # ========== PERMITIR LOOPBACK ==========

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # ========== PROTECCIÓN ICMP (PING) ==========
    # Permisivo para tu ping cada 30s

    iptables -A DDOS_PROTECT -p icmp --icmp-type echo-request -m limit \
        --limit ${ICMP_LIMIT}/s --limit-burst $ICMP_BURST -j ACCEPT

    iptables -A DDOS_PROTECT -p icmp --icmp-type echo-reply -j ACCEPT

    # Bloquear flood de ICMP
    iptables -A DDOS_PROTECT -p icmp --icmp-type echo-request -j DROP

    # ========== PROTECCIÓN SSH (TU CASO) ==========

    # Permitir SSH establecido sin límites
    iptables -A SSH_PROTECT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT

    # Rate limiting solo para NUEVOS intentos de conexión SSH
    # Esto previene fuerza bruta pero no afecta tu sesión activa
    iptables -A SSH_PROTECT -p tcp --dport "$SSH_PORT" --syn -m recent --name ssh_new --set

    # Bloquear si hay más de MAX_SSH_ATTEMPTS intentos nuevos por minuto
    iptables -A SSH_PROTECT -p tcp --dport "$SSH_PORT" --syn -m recent --name ssh_new \
        --update --seconds 60 --hitcount "$MAX_SSH_ATTEMPTS" -j SET --add-set blocked_ips src --exist

    iptables -A SSH_PROTECT -p tcp --dport "$SSH_PORT" --syn -m recent --name ssh_new \
        --update --seconds 60 --hitcount "$MAX_SSH_ATTEMPTS" -j DROP

    # Limitar conexiones SSH simultáneas (pero permisivo)
    iptables -A SSH_PROTECT -p tcp --dport "$SSH_PORT" -m connlimit \
        --connlimit-above "$MAX_SSH_CONN_PER_IP" --connlimit-mask 32 -j REJECT --reject-with tcp-reset

    # Aceptar SSH válido
    iptables -A SSH_PROTECT -p tcp --dport "$SSH_PORT" -j ACCEPT

    log "Protección SSH configurada (sesiones establecidas ilimitadas)"

    # ========== PROTECCIÓN CONTRA SYN FLOOD ==========

    iptables -A DDOS_PROTECT -p tcp --syn -m limit \
        --limit ${SYN_FLOOD_LIMIT}/s --limit-burst $((SYN_FLOOD_LIMIT * 3)) -j RETURN

    # Marcar IPs con demasiados SYN como sospechosas
    iptables -A DDOS_PROTECT -p tcp --syn -j SET --add-set suspicious_ips src --exist
    iptables -A DDOS_PROTECT -p tcp --syn -j DROP

    # ========== PROTECCIÓN CONTRA UDP FLOOD ==========

    iptables -A DDOS_PROTECT -p udp -m limit \
        --limit ${UDP_FLOOD_LIMIT}/s --limit-burst $((UDP_FLOOD_LIMIT * 2)) -j RETURN

    iptables -A DDOS_PROTECT -p udp -j DROP

    # ========== PROTECCIÓN HTTP/HTTPS ==========
    # Límites generosos para usuarios reales

    # Permitir conexiones HTTP establecidas sin límite
    iptables -A HTTP_PROTECT -p tcp --dport "$HTTP_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A HTTP_PROTECT -p tcp --dport "$HTTPS_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT

    # Rate limiting para NUEVAS conexiones HTTP
    iptables -A HTTP_PROTECT -p tcp --dport "$HTTP_PORT" --syn -m recent --name http_new --set
    iptables -A HTTP_PROTECT -p tcp --dport "$HTTP_PORT" --syn -m recent --name http_new \
        --update --seconds 60 --hitcount "$MAX_HTTP_REQUESTS" -j SET --add-set suspicious_ips src --exist

    iptables -A HTTP_PROTECT -p tcp --dport "$HTTPS_PORT" --syn -m recent --name https_new --set
    iptables -A HTTP_PROTECT -p tcp --dport "$HTTPS_PORT" --syn -m recent --name https_new \
        --update --seconds 60 --hitcount "$MAX_HTTP_REQUESTS" -j SET --add-set suspicious_ips src --exist

    # Limitar conexiones HTTP simultáneas
    iptables -A HTTP_PROTECT -p tcp -m multiport --dports "$HTTP_PORT","$HTTPS_PORT" \
        -m connlimit --connlimit-above "$MAX_HTTP_CONN_PER_IP" --connlimit-mask 32 -j DROP

    # Aceptar HTTP/HTTPS válido
    iptables -A HTTP_PROTECT -p tcp -m multiport --dports "$HTTP_PORT","$HTTPS_PORT" -j ACCEPT

    # ========== LÍMITE GENERAL DE CONEXIONES ==========
    # Solo para conexiones NUEVAS, no afecta las establecidas

    iptables -A RATE_LIMIT -m conntrack --ctstate NEW -m recent --name conn_rate --set
    iptables -A RATE_LIMIT -m conntrack --ctstate NEW -m recent --name conn_rate \
        --update --seconds 1 --hitcount "$MAX_NEW_CONN_RATE" -j SET --add-set suspicious_ips src --exist

    # Limitar total de conexiones por IP
    iptables -A RATE_LIMIT -m connlimit --connlimit-above "$MAX_CONN_PER_IP" --connlimit-mask 32 \
        -j SET --add-set blocked_ips src --exist
    iptables -A RATE_LIMIT -m connlimit --connlimit-above "$MAX_CONN_PER_IP" --connlimit-mask 32 -j DROP

    # ========== DETECCIÓN DE BOTS ==========
    # IPs sospechosas son monitoreadas más de cerca

    iptables -A BOT_DETECT -m set --match-set suspicious_ips src -m recent --name bot_check --set
    iptables -A BOT_DETECT -m set --match-set suspicious_ips src -m recent --name bot_check \
        --update --seconds "$BOT_DETECTION_WINDOW" --hitcount "$BOT_NEW_CONN_THRESHOLD" \
        -j SET --add-set blocked_ips src --exist
    iptables -A BOT_DETECT -m set --match-set suspicious_ips src -m recent --name bot_check \
        --update --seconds "$BOT_DETECTION_WINDOW" --hitcount "$BOT_NEW_CONN_THRESHOLD" -j DROP

    # ========== PROTECCIÓN CONTRA PAQUETES INVÁLIDOS ==========

    # Limitar paquetes inválidos
    iptables -A INPUT -m conntrack --ctstate INVALID -m limit --limit ${INVALID_PACKET_LIMIT}/s -j DROP
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Protección contra escaneos
    iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

    # Protección contra ataques comunes
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

    # ========== APLICAR CADENAS EN ORDEN ==========

    iptables -A INPUT -j DDOS_PROTECT
    iptables -A INPUT -j SSH_PROTECT
    iptables -A INPUT -j HTTP_PROTECT
    iptables -A INPUT -j RATE_LIMIT
    iptables -A INPUT -j BOT_DETECT

    log "Reglas de iptables configuradas (optimizado para usuarios reales)"
}

# ==================== CONTROL DE ANCHO DE BANDA (TC) ====================

setup_traffic_control() {
    log "Configurando control de tráfico (TC)..."

    # Limpiar configuración anterior
    tc qdisc del dev "$INTERFACE" root 2>/dev/null || true

    # Crear qdisc raíz HTB
    tc qdisc add dev "$INTERFACE" root handle 1: htb default 30

    # Clase raíz con límite global
    tc class add dev "$INTERFACE" parent 1: classid 1:1 htb rate "$GLOBAL_MAX_BANDWIDTH"

    # Clase para IPs de confianza (alta prioridad y ancho de banda)
    tc class add dev "$INTERFACE" parent 1:1 classid 1:10 htb rate "$TRUSTED_BANDWIDTH" \
        ceil "$GLOBAL_MAX_BANDWIDTH" prio 1

    # Clase para usuarios normales validados
    tc class add dev "$INTERFACE" parent 1:1 classid 1:20 htb rate "$FILE_TRANSFER_BANDWIDTH" \
        ceil "$GLOBAL_MAX_BANDWIDTH" prio 2

    # Clase para tráfico general
    tc class add dev "$INTERFACE" parent 1:1 classid 1:30 htb rate "$MAX_BANDWIDTH_PER_IP" \
        ceil "$GLOBAL_MAX_BANDWIDTH" prio 3

    # Fair Queue para cada clase
    tc qdisc add dev "$INTERFACE" parent 1:10 handle 10: sfq perturb 10
    tc qdisc add dev "$INTERFACE" parent 1:20 handle 20: sfq perturb 10
    tc qdisc add dev "$INTERFACE" parent 1:30 handle 30: sfq perturb 10

    # Filtros para clasificar tráfico
    # SSH y transferencias de archivos a clase prioritaria
    tc filter add dev "$INTERFACE" protocol ip parent 1:0 prio 1 u32 \
        match ip sport "$SSH_PORT" 0xffff flowid 1:10
    tc filter add dev "$INTERFACE" protocol ip parent 1:0 prio 1 u32 \
        match ip dport "$SSH_PORT" 0xffff flowid 1:10

    log "Control de tráfico configurado (SSH prioritario)"
}

# ==================== MONITOREO INTELIGENTE ====================

monitor_connections() {
    log "Iniciando monitoreo inteligente de conexiones..."

    while true; do
        # Analizar patrones de comportamiento
        netstat -ntu | awk 'NR>2 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -50 | while read -r count ip; do
            # Ignorar localhost, IPs vacías y IPs de confianza
            [[ "$ip" == "127.0.0.1" || -z "$ip" || "$ip" == "0.0.0.0" ]] && continue

            # Si la IP está en trusted, saltarla
            if ipset test trusted_ips "$ip" 2>/dev/null; then
                continue
            fi

            # Análisis de comportamiento bot vs humano
            local established_count short_lived_count new_count
            established_count=$(netstat -ntu | grep "$ip" | grep -c "ESTABLISHED" || echo 0)
            short_lived_count=$(netstat -ntu | grep "$ip" | grep -cE "TIME_WAIT|CLOSE_WAIT" || echo 0)
            new_count=$(netstat -ntu | grep "$ip" | grep -c "SYN_SENT\|SYN_RECV" || echo 0)

            # Bot típico: muchas conexiones nuevas, pocas establecidas
            if [[ $count -gt 200 && $established_count -lt 10 ]]; then
                if ! ipset test whitelist_ips "$ip" 2>/dev/null; then
                    log "BOT DETECTADO: IP $ip - $count conexiones, solo $established_count establecidas"
                    ipset add -exist blocked_ips "$ip"
                    echo "$(date +%s) $ip bot_pattern" >> "$BLOCKLIST_FILE"
                fi
            # Usuario real: mantiene conexiones establecidas
            elif [[ $established_count -gt 5 && $count -lt $MAX_CONN_PER_IP ]]; then
                # Agregar a whitelist automática por buen comportamiento
                ipset add -exist whitelist_ips "$ip" timeout 86400
                log "Usuario legítimo validado: $ip ($established_count conexiones estables)"
            fi
        done

        sleep 30
    done
}

# ==================== GESTIÓN DE IPS ====================

add_trusted_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ipset add -exist trusted_ips "$ip"
        echo "$ip" >> "$TRUSTED_FILE"
        sort -u "$TRUSTED_FILE" -o "$TRUSTED_FILE"
        log "IP $ip añadida como CONFIABLE (acceso total)"
    else
        error "IP inválida: $ip"
    fi
}

add_to_whitelist() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ipset add -exist whitelist_ips "$ip" timeout 0
        echo "$ip" >> "$WHITELIST_FILE"
        sort -u "$WHITELIST_FILE" -o "$WHITELIST_FILE"
        log "IP $ip añadida a whitelist"
    else
        error "IP inválida: $ip"
    fi
}

remove_from_blocklist() {
    local ip="$1"
    ipset del blocked_ips "$ip" 2>/dev/null || true
    ipset del suspicious_ips "$ip" 2>/dev/null || true
    sed -i "/^[0-9]* $ip /d" "$BLOCKLIST_FILE"
    log "IP $ip removida de blocklist"
}

show_status() {
    echo "==================== ESTADO DEL SISTEMA ===================="
    echo ""
    echo "=== IPs DE CONFIANZA (Acceso Total) ==="
    ipset list trusted_ips 2>/dev/null | grep -A 100 "Members:" | tail -n +2 | head -20 || echo "Ninguna"
    echo ""
    echo "=== IPs EN WHITELIST (Usuarios Validados) ==="
    ipset list whitelist_ips 2>/dev/null | grep -A 100 "Members:" | tail -n +2 | head -20 || echo "Ninguna"
    echo ""
    echo "=== IPs BLOQUEADAS ==="
    ipset list blocked_ips 2>/dev/null | grep -A 100 "Members:" | tail -n +2 | head -20 || echo "Ninguna"
    echo ""
    echo "=== IPs SOSPECHOSAS (En Observación) ==="
    ipset list suspicious_ips 2>/dev/null | grep -A 100 "Members:" | tail -n +2 | head -10 || echo "Ninguna"
    echo ""
    echo "=== TOP 15 CONEXIONES ACTUALES ==="
    netstat -ntu | awk 'NR>2 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -15
    echo ""
    echo "=== ESTADÍSTICAS DE CONEXIONES ESTABLECIDAS ==="
    echo "SSH establecidas: $(netstat -ntu | grep ":$SSH_PORT" | grep -c ESTABLISHED || echo 0)"
    echo "HTTP establecidas: $(netstat -ntu | grep ":$HTTP_PORT\|:$HTTPS_PORT" | grep -c ESTABLISHED || echo 0)"
    echo "Total establecidas: $(netstat -ntu | grep -c ESTABLISHED || echo 0)"
    echo ""
    echo "=== ÚLTIMOS BLOQUEOS (últimas 10 líneas) ==="
    tail -10 "$BLOCKLIST_FILE" 2>/dev/null || echo "Sin bloqueos recientes"
    echo "==========================================================="
}

# ==================== LIMPIEZA ====================

cleanup() {
    log "Limpiando configuración..."

    # Eliminar reglas de iptables
    iptables -D INPUT -j DDOS_PROTECT 2>/dev/null || true
    iptables -D INPUT -j SSH_PROTECT 2>/dev/null || true
    iptables -D INPUT -j HTTP_PROTECT 2>/dev/null || true
    iptables -D INPUT -j RATE_LIMIT 2>/dev/null || true
    iptables -D INPUT -j BOT_DETECT 2>/dev/null || true

    iptables -F DDOS_PROTECT 2>/dev/null || true
    iptables -F SSH_PROTECT 2>/dev/null || true
    iptables -F HTTP_PROTECT 2>/dev/null || true
    iptables -F RATE_LIMIT 2>/dev/null || true
    iptables -F BOT_DETECT 2>/dev/null || true

    iptables -X DDOS_PROTECT 2>/dev/null || true
    iptables -X SSH_PROTECT 2>/dev/null || true
    iptables -X HTTP_PROTECT 2>/dev/null || true
    iptables -X RATE_LIMIT 2>/dev/null || true
    iptables -X BOT_DETECT 2>/dev/null || true

    # Eliminar ipsets
    ipset destroy blocked_ips 2>/dev/null || true
    ipset destroy whitelist_ips 2>/dev/null || true
    ipset destroy trusted_ips 2>/dev/null || true
    ipset destroy suspicious_ips 2>/dev/null || true
    ipset destroy http_recent 2>/dev/null || true
    ipset destroy ssh_recent 2>/dev/null || true

    # Eliminar TC
    tc qdisc del dev "$INTERFACE" root 2>/dev/null || true

    log "Limpieza completada"
}

# ==================== MAIN ====================

main() {
    local action="${1:-start}"

    check_root
    check_dependencies
    setup_directories

    case "$action" in
        start)
            log "=== Iniciando sistema de protección MEJORADO ==="
            create_ipsets
            setup_iptables
            setup_traffic_control
            log "=== Sistema activado (optimizado para usuarios reales) ==="
            echo ""
            echo "IMPORTANTE:"
            echo "1. Añade TU IP como confiable: sudo $0 trust $(curl -s ifconfig.me)"
            echo "2. Las sesiones SSH establecidas NO tienen límites"
            echo "3. Tu ping cada 30s está permitido sin problemas"
            echo "4. Transferencias de archivos tienen prioridad"
            ;;

        stop)
            cleanup
            ;;

        restart)
            cleanup
            sleep 2
            main start
            ;;

        monitor)
            monitor_connections
            ;;

        status)
            show_status
            ;;

        trust)
            [[ -z "${2:-}" ]] && { error "Uso: $0 trust <IP>"; exit 1; }
            add_trusted_ip "$2"
            ;;

        whitelist)
            [[ -z "${2:-}" ]] && { error "Uso: $0 whitelist <IP>"; exit 1; }
            add_to_whitelist "$2"
            ;;

        unblock)
            [[ -z "${2:-}" ]] && { error "Uso: $0 unblock <IP>"; exit 1; }
            remove_from_blocklist "$2"
            ;;

        *)
            echo "Uso: $0 {start|stop|restart|monitor|status|trust <IP>|whitelist <IP>|unblock <IP>}"
            echo ""
            echo "Comandos:"
            echo "  start     - Iniciar protección"
            echo "  stop      - Detener protección"
            echo "  restart   - Reiniciar protección"
            echo "  monitor   - Monitorear en tiempo real"
            echo "  status    - Ver estado actual"
            echo "  trust IP  - Añadir IP de confianza (acceso total, sin límites)"
            echo "  whitelist IP - Añadir IP a whitelist (límites generosos)"
            echo "  unblock IP   - Desbloquear IP"
            exit 1
            ;;
    esac
}

trap cleanup EXIT INT TERM

main "$@"
