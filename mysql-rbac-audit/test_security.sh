#!/bin/bash

# 1. Obtener la ruta exacta del proyecto
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Crear subcarpeta logs dentro de mysql-rbac-audit
mkdir -p "$MODULE_DIR/logs"

# 3. Definir la ruta fija del log
LOGFILE="$MODULE_DIR/logs/auditoria.log"

echo "$(date) - Iniciando pruebas de seguridad MySQL RBAC" | tee -a "$LOGFILE"

echo "=== [1/3] Inserción legítima con usuario operador ===" | tee -a "$LOGFILE"
mysql -u usr_auditor -pAuditorPass123! -e "USE auditoria_acceso; INSERT INTO registro_accesos (usuario, ip_origen, accion) VALUES ('soc_analyst', '192.168.1.50', 'SECURITY_SCAN');" >> "$LOGFILE" 2>&1

echo -e "\n=== [2/3] Borrado NO AUTORIZADO (Debe fallar - ERROR 1142) ===" | tee -a "$LOGFILE"
mysql -u usr_auditor -pAuditorPass123! -e "USE auditoria_acceso; DELETE FROM registro_accesos WHERE id = 1;" >> "$LOGFILE" 2>&1

echo -e "\n=== [3/3] Consulta con usuario lector ===" | tee -a "$LOGFILE"
mysql -u usr_consulta -pConsultaPass123! -e "USE auditoria_acceso; SELECT * FROM registro_accesos;" >> "$LOGFILE" 2>&1

echo "$(date) - Pruebas finalizadas" | tee -a "$LOGFILE"
