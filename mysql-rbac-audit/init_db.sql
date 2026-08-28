-- ====================================================
-- PROYECTO: DB Hardening & RBAC Audit System
-- OBJETIVO: Implementación de menor privilegio y logs
-- ====================================================

-- 1. Limpieza de entorno previo
DROP DATABASE IF EXISTS auditoria_acceso;
DROP USER IF EXISTS 'usr_consulta'@'localhost';
DROP USER IF EXISTS 'usr_auditor'@'localhost';
DROP ROLE IF EXISTS 'rol_lector';
DROP ROLE IF EXISTS 'rol_operador';

-- 2. Creación del esquema de seguridad
CREATE DATABASE auditoria_acceso;
USE auditoria_acceso;

-- 3. Tabla de registros (Anti-Tampering)
CREATE TABLE registro_accesos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario VARCHAR(50) NOT NULL,
    ip_origen VARCHAR(45) NOT NULL,
    accion VARCHAR(100) NOT NULL,
    fecha_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insertar evento base
INSERT INTO registro_accesos (usuario, ip_origen, accion) 
VALUES ('system_init', '127.0.0.1', 'INITIAL_DEPLOYMENT');

-- 4. Definición de Roles (RBAC)
CREATE ROLE 'rol_lector';
CREATE ROLE 'rol_operador';

-- Asignación estricta de privilegios
GRANT SELECT ON auditoria_acceso.* TO 'rol_lector';
GRANT SELECT, INSERT ON auditoria_acceso.* TO 'rol_operador';

-- 5. Creación de usuarios con contraseñas de prueba
CREATE USER 'usr_consulta'@'localhost' IDENTIFIED BY 'ConsultaPass123!';
CREATE USER 'usr_auditor'@'localhost' IDENTIFIED BY 'AuditorPass123!';

-- Asignación y activación de roles
GRANT 'rol_lector' TO 'usr_consulta'@'localhost';
GRANT 'rol_operador' TO 'usr_auditor'@'localhost';

SET DEFAULT ROLE 'rol_lector' FOR 'usr_consulta'@'localhost';
SET DEFAULT ROLE 'rol_operador' FOR 'usr_auditor'@'localhost';

FLUSH PRIVILEGES;
