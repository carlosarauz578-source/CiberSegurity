# Proyecto Semana 5 – Roles Seguros en MySQL/MariaDB

## 1. Introducción

Este proyecto documenta la implementación de un sistema de auditoría, control de acceso basado en roles (RBAC) y registro de intentos de acceso fallidos sobre una base de datos MariaDB/MySQL. 

El entorno de trabajo se desarrolló en una máquina virtual con **Kali Linux**, la cual fue administrada de manera remota desde la interfaz de **Visual Studio Code** mediante la extensión **Remote - SSH**. El objetivo principal fue crear una arquitectura segura en la base de datos `seguridad`, limitar los privilegios de conexión del script de automatización mediante el usuario dedicado `python_user`, e implementar herramientas en Python para auditar la base de datos, analizar logs de autenticación de Linux y generar informes forenses automatizados.

---

## 2. Guía Paso a Paso

### 2.1. Conexión de VS Code a Kali Linux vía Remote - SSH
1. En VS Code, instalar la extensión **Remote - SSH**.
2. Abrir la paleta de comandos (`Ctrl + Shift + P` o `F1`) y seleccionar `Remote-SSH: Connect to Host...`.
3. Introducir la dirección de conexión del usuario en Kali Linux:
   `ssh usuario@IP_DE_KALI`
4. Ingresar la contraseña y seleccionar el directorio de trabajo donde se alojará el repositorio.

### 2.2. Estructura de Directorios Inicial
Dentro de la terminal integrada de VS Code en Kali, se creó la carpeta del módulo:
`mkdir -p msql-segurity`

### 2.3. Instalación de Dependencias
Se actualizaron los repositorios del sistema, se instaló el servidor MariaDB y las librerías necesarias:

```bash
# Actualización del sistema
sudo apt update && sudo apt upgrade -y

# Instalación de MariaDB Server
sudo apt install mariadb-server -y

# Asegurar y levantar el servicio de MariaDB
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Instalación del conector de MySQL para Python
pip install mysql-connector-python python-dotenv

#!/bin/bash
# Script de automatización de entorno y despliegue

chmod +x deploy.sh
echo "[+] Permisos de ejecución asignados a deploy.sh"

# Ejecución de scripts de prueba
python3 msql-segurity/registrar_accesos.py
python3 msql-segurity/auditoria_db.py
sudo python3 msql-segurity/analizador_auth.py
