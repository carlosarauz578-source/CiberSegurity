# REST API Auditable en Node.js (Express & MySQL)

Servicio REST API desarrollado en Node.js y Express diseñado para recibir, autenticar y almacenar registros de auditoría de acceso en una base de datos MariaDB/MySQL, manteniendo una copia local en archivos de log aislados.

## Features

* **Autenticación HTTP Basic:** Protección de endpoints mediante credenciales configurables.
* **Persistencia Dual:** Registra eventos directamente en base de datos relacional (MySQL) y en un log local en sistema de archivos (`logs/api_access.log`).
* **Seguridad y Menor Privilegio:** Operación mediante usuario dedicado de base de datos (`usr_api`).
* **Variables de Entorno:** Aislamiento total de credenciales mediante el uso de `.env`.

## Requisitos Previos

* Node.js (v18+)
* MariaDB / MySQL Server

## Configuración e Instalación

1. **Instalar dependencias:**
   ```bash
   npm install