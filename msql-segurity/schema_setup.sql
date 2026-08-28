-- 1. Creación de la base de datos de seguridad
CREATE DATABASE IF NOT EXISTS seguridad;
USE seguridad;

-- 2. Creación de la tabla para auditoría de accesos
CREATE TABLE IF NOT EXISTS accesos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario VARCHAR(50) NOT NULL,
    ip_origen VARCHAR(45) NOT NULL,
    estado VARCHAR(20) NOT NULL, -- 'Exitoso' o 'Fallido'
    fecha_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Creación del usuario con privilegios restringidos
CREATE USER IF NOT EXISTS 'python_user'@'localhost' IDENTIFIED BY 'PasswordSegura2026!';

-- 4. Asignación de privilegios mínimos necesarios (Principio de Mínimo Privilegio)
GRANT INSERT, SELECT ON seguridad.accesos TO 'python_user'@'localhost';

-- 5. Aplicar cambios de privilegios
FLUSH PRIVILEGES;
