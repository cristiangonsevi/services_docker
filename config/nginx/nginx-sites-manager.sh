#!/usr/bin/env bash
set -euo pipefail

# Script para gestionar enlaces simbólicos de configuraciones nginx
# Uso: ./nginx-sites-manager.sh [enable|disable|status|list] [sitename]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITES_AVAILABLE="$SCRIPT_DIR"
SITES_ENABLED="/etc/nginx/sites-enabled"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Este script necesita permisos de root."
        log_info "Ejecuta: sudo $0 $*"
        exit 1
    fi
}

# List available sites
list_available_sites() {
    log_info "Sitios disponibles en $SITES_AVAILABLE:"
    for site in "$SITES_AVAILABLE"/*.{com,conf}; do
        [ -f "$site" ] || continue
        basename "$site"
    done 2>/dev/null | sort
}

# List enabled sites
list_enabled_sites() {
    log_info "Sitios habilitados en $SITES_ENABLED:"
    if [ -d "$SITES_ENABLED" ]; then
        for link in "$SITES_ENABLED"/*; do
            [ -L "$link" ] || continue
            basename "$link"
        done | sort
    else
        log_warning "Directorio $SITES_ENABLED no existe"
    fi
}

# Show status of all sites
show_status() {
    log_info "Estado de configuraciones nginx:"
    echo
    printf "%-25s %-10s %-10s\n" "SITIO" "DISPONIBLE" "HABILITADO"
    printf "%-25s %-10s %-10s\n" "-----" "----------" "----------"

    # Get all unique site names
    local sites=()
    for site in "$SITES_AVAILABLE"/*.{com,conf}; do
        [ -f "$site" ] || continue
        sites+=($(basename "$site"))
    done 2>/dev/null

    # Sort sites
    IFS=$'\n' sites=($(sort <<<"${sites[*]}"))
    unset IFS

    for site in "${sites[@]}"; do
        local available="✓"
        local enabled="✗"

        if [ -L "$SITES_ENABLED/$site" ]; then
            enabled="✓"
        fi

        printf "%-25s %-10s %-10s\n" "$site" "$available" "$enabled"
    done
}

# Enable a site
enable_site() {
    local site="$1"
    local source_file="$SITES_AVAILABLE/$site"
    local target_link="$SITES_ENABLED/$site"

    # Check if source file exists
    if [ ! -f "$source_file" ]; then
        log_error "Archivo de configuración '$site' no encontrado en $SITES_AVAILABLE"
        return 1
    fi

    # Create sites-enabled directory if it doesn't exist
    if [ ! -d "$SITES_ENABLED" ]; then
        log_info "Creando directorio $SITES_ENABLED"
        mkdir -p "$SITES_ENABLED"
    fi

    # Check if already enabled
    if [ -L "$target_link" ]; then
        log_warning "El sitio '$site' ya está habilitado"
        return 0
    fi

    # Create symbolic link
    if ln -s "$source_file" "$target_link"; then
        log_success "Sitio '$site' habilitado correctamente"
        log_info "Enlace creado: $target_link -> $source_file"
        return 0
    else
        log_error "Error al crear enlace simbólico para '$site'"
        return 1
    fi
}

# Disable a site
disable_site() {
    local site="$1"
    local target_link="$SITES_ENABLED/$site"

    # Check if link exists
    if [ ! -L "$target_link" ]; then
        log_warning "El sitio '$site' no está habilitado"
        return 0
    fi

    # Remove symbolic link
    if rm "$target_link"; then
        log_success "Sitio '$site' deshabilitado correctamente"
        return 0
    else
        log_error "Error al eliminar enlace simbólico para '$site'"
        return 1
    fi
}

# Enable all sites
enable_all() {
    log_info "Habilitando todos los sitios disponibles..."
    local count=0
    local errors=0

    for site in "$SITES_AVAILABLE"/*.{com,conf}; do
        [ -f "$site" ] || continue
        local sitename=$(basename "$site")

        if enable_site "$sitename"; then
            ((count++))
        else
            ((errors++))
        fi
    done 2>/dev/null

    log_info "Procesados: $count sitios habilitados, $errors errores"
}

# Disable all sites
disable_all() {
    log_info "Deshabilitando todos los sitios..."
    local count=0
    local errors=0

    if [ -d "$SITES_ENABLED" ]; then
        for link in "$SITES_ENABLED"/*; do
            [ -L "$link" ] || continue
            local sitename=$(basename "$link")

            if disable_site "$sitename"; then
                ((count++))
            else
                ((errors++))
            fi
        done
    fi

    log_info "Procesados: $count sitios deshabilitados, $errors errores"
}

# Test nginx configuration
test_nginx() {
    log_info "Probando configuración de nginx..."
    if nginx -t; then
        log_success "Configuración de nginx válida"
        return 0
    else
        log_error "Error en la configuración de nginx"
        return 1
    fi
}

# Reload nginx
reload_nginx() {
    log_info "Recargando nginx..."
    if systemctl reload nginx; then
        log_success "Nginx recargado correctamente"
        return 0
    else
        log_error "Error al recargar nginx"
        return 1
    fi
}

# Show usage
show_usage() {
    echo "Gestión de sitios nginx"
    echo
    echo "Uso: $0 [COMANDO] [SITIO]"
    echo
    echo "COMANDOS:"
    echo "  enable SITIO     Habilita un sitio específico"
    echo "  disable SITIO    Deshabilita un sitio específico"
    echo "  enable-all       Habilita todos los sitios disponibles"
    echo "  disable-all      Deshabilita todos los sitios"
    echo "  status           Muestra el estado de todos los sitios"
    echo "  list             Lista sitios disponibles y habilitados"
    echo "  test             Prueba la configuración de nginx"
    echo "  reload           Recarga nginx (después de hacer cambios)"
    echo "  help             Muestra esta ayuda"
    echo
    echo "EJEMPLOS:"
    echo "  $0 enable vault.crisego.com"
    echo "  $0 disable ntfy.crisego.com"
    echo "  $0 enable-all"
    echo "  $0 status"
    echo "  $0 test && $0 reload"
    echo
}

# Main script logic
main() {
    local command="${1:-help}"

    case "$command" in
        "enable")
            [ $# -eq 2 ] || { log_error "Uso: $0 enable SITIO"; exit 1; }
            check_root
            enable_site "$2"
            ;;
        "disable")
            [ $# -eq 2 ] || { log_error "Uso: $0 disable SITIO"; exit 1; }
            check_root
            disable_site "$2"
            ;;
        "enable-all")
            check_root
            enable_all
            ;;
        "disable-all")
            check_root
            disable_all
            ;;
        "status")
            show_status
            ;;
        "list")
            echo
            list_available_sites
            echo
            list_enabled_sites
            echo
            ;;
        "test")
            check_root
            test_nginx
            ;;
        "reload")
            check_root
            test_nginx && reload_nginx
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            log_error "Comando desconocido: $command"
            echo
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
