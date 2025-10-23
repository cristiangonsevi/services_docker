#!/bin/bash
# Script para verificar Docker y crear red compartida + configs globales
# Autor: GitHub Copilot

set -e

# 1. Verificar si Docker está instalado
echo "Verificando instalación de Docker..."
if ! command -v docker &> /dev/null; then
    echo "Docker no está instalado. Por favor, instálalo antes de continuar."
    exit 1
fi
echo "Docker está instalado."

# 2. Crear red compartida si no existe
NETWORK_NAME="shared_net"
echo "Creando red Docker compartida: $NETWORK_NAME"
if ! docker network inspect "$NETWORK_NAME" &> /dev/null; then
    docker network create --driver bridge "$NETWORK_NAME"
    echo "Red $NETWORK_NAME creada."
else
    echo "La red $NETWORK_NAME ya existe."
fi

# 3. Configuración global de Docker (ejemplo: logging driver, DNS)
# Puedes agregar más opciones según tus necesidades
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
echo "Configurando opciones globales de Docker (logging driver, DNS)..."

# Backup de configuración actual
if [ -f "$DOCKER_DAEMON_JSON" ]; then
    cp "$DOCKER_DAEMON_JSON" "$DOCKER_DAEMON_JSON.bak"
    echo "Backup de $DOCKER_DAEMON_JSON creado."
fi

# Configuración recomendada (puedes modificar)
cat <<EOF > "$DOCKER_DAEMON_JSON"
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "dns": ["8.8.8.8", "1.1.1.1"]
}
EOF

echo "Configuración global aplicada. Reiniciando Docker..."
systemctl restart docker

echo "Script completado. Puedes conectar tus contenedores a la red $NETWORK_NAME."
