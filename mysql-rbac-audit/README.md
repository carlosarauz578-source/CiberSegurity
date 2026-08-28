# MySQL/MariaDB RBAC & Audit System

Este proyecto implementa el principio de menor privilegio (PoLP) y mecanismos anti-tampering en MariaDB sobre Kali Linux.

## Estructura del Módulo
* `init_db.sql`: Despliegue del esquema auditoria_acceso, creación de tablas, usuarios y roles (`rol_lector`, `rol_operador`)
* `test_security.sh`: Script de validación automatizada de permisos y prueba de bloqueo anti-tampering (ERROR 1142)
* `.gitignore`: Filtro de exclusión para logs y archivos sensibles

## Mecanismos de Seguridad
* **rol_lector**: Acceso exclusivo a SELECT para analistas de monitoreo o SOC.
* **rol_operador**: Acceso a SELECT e INSERT. Bloqueo estricto de comandos destructivos (DELETE, DROP).

## Ejecución
```bash
# 1. Desplegar base de datos y permisos
sudo mysql < init_db.sql

# 2. Ejecutar prueba de seguridad
./test_security.sh
```
