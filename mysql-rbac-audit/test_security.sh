#!/bin/bash

echo "=== [1/3] Inserción legítima con usuario operador ==="
mysql -u usr_auditor -pAuditorPass123! -e "USE auditoria_acceso; INSERT INTO registro_accesos (usuario, ip_origen, accion) VALUES ('soc_analyst', '192.168.1.50', 'SECURITY_SCAN');"

echo -e "\n=== [2/3] Borrado NO AUTORIZADO (Debe fallar - ERROR 1142) ==="
mysql -u usr_auditor -pAuditorPass123! -e "USE auditoria_acceso; DELETE FROM registro_accesos WHERE id = 1;"

echo -e "\n=== [3/3] Consulta con usuario lector ==="
mysql -u usr_consulta -pConsultaPass123! -e "USE auditoria_acceso; SELECT * FROM registro_accesos;"
