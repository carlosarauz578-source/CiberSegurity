#!/usr/bin/env python3
"""
Módulo de Auditoría de Accesos y Detección de Anomalías
Autor: Ciberseguridad Lab
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
import pymysql
from pymysql.err import MySQLError, OperationalError

# Determinar el directorio exacto donde vive este script y definir la carpeta logs
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

DEFAULT_LOGFILE = os.path.join(LOGS_DIR, "auditoria.log")
DEFAULT_JSONFILE = os.path.join(LOGS_DIR, "alertas.json")

# Configuración de argumentos CLI
parser = argparse.ArgumentParser(
    description="Sistema de Auditoría de Accesos y Detección de Fuerza Bruta en MariaDB",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument("--umbral", type=int, default=int(os.getenv("AUDIT_UMBRAL", 2)), help="Umbral de intentos fallidos para disparar alerta")
parser.add_argument("--minutos", type=int, default=int(os.getenv("AUDIT_MINUTOS", 10)), help="Ventana de tiempo en minutos a inspeccionar")
parser.add_argument("--logfile", type=str, default=DEFAULT_LOGFILE, help="Ruta del archivo de log del sistema")
parser.add_argument("--jsonfile", type=str, default=DEFAULT_JSONFILE, help="Ruta de exportación de alertas en JSON")
parser.add_argument("--host", type=str, default=os.getenv("DB_HOST", "localhost"), help="Host de la base de datos")
parser.add_argument("--user", type=str, default=os.getenv("DB_USER", "auditor"), help="Usuario de la base de datos")
parser.add_argument("--password", type=str, default=os.getenv("DB_PASS", "password"), help="Contraseña de la base de datos")
parser.add_argument("--db", type=str, default=os.getenv("DB_NAME", "seguridad"), help="Nombre de la base de datos")
args = parser.parse_args()

# Estilos de formato ANSI para la consola
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_RESET = "\033[0m"

# Configuración del sistema de Logging
logging.basicConfig(
    filename=args.logfile,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (PID:%(process)d) - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def guardar_alertas_json(nuevas_alertas, ruta_archivo):
    """Guarda las alertas manteniendo el historial existente en formato JSON."""
    alertas_existentes = []
    if os.path.exists(ruta_archivo):
        try:
            with open(ruta_archivo, "r", encoding="utf-8") as f:
                alertas_existentes = json.load(f)
        except json.JSONDecodeError:
            logging.warning(f"El archivo {ruta_archivo} estaba dañado. Se sobrescribirá.")

    alertas_existentes.extend(nuevas_alertas)
    
    # Escritura atómica mediante archivo temporal
    temp_file = f"{ruta_archivo}.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(alertas_existentes, f, indent=4, ensure_ascii=False)
    os.replace(temp_file, ruta_archivo)

def procesar_auditoria():
    conexion = None
    alertas = []
    conteo_ips = {}

    print(f"\n=== {COLOR_GREEN}INICIANDO PROCESAMIENTO DE AUDITORÍA{COLOR_RESET} ===")
    print(f"[*] Inspeccionando eventos de los últimos {args.minutos} minutos...")

    try:
        conexion = pymysql.connect(
            host=args.host,
            user=args.user,
            password=args.password,
            database=args.db,
            connect_timeout=5
        )

        with conexion.cursor(pymysql.cursors.DictCursor) as cursor:
            query = """
                SELECT usuario, ip_origen AS ip, fecha_hora AS fecha 
                FROM registro_accesos 
                WHERE 1=1 
                  AND fecha_hora >= NOW() - INTERVAL %s MINUTE
            """
            cursor.execute(query, (args.minutos,))
            registros = cursor.fetchall()

            if not registros:
                print(f"[*] {COLOR_GREEN}Sin intentos fallidos detectados en el periodo especificado.{COLOR_RESET}")
                return

            for reg in registros:
                usuario, ip, fecha = reg['usuario'], reg['ip'], str(reg['fecha'])
                mensaje = f"Intento fallido detectado | Usuario: {usuario} | IP: {ip} | Fecha: {fecha}"
                
                print(f"{COLOR_YELLOW}[LOG]{COLOR_RESET} {mensaje}")
                logging.info(mensaje)

                conteo_ips[ip] = conteo_ips.get(ip, 0) + 1

        for ip, total in conteo_ips.items():
            if total >= args.umbral:
                alerta_data = {
                    "timestamp": datetime.now().isoformat(),
                    "ip_origen": ip,
                    "eventos_fallidos": total,
                    "nivel_riesgo": "CRÍTICO" if total >= args.umbral * 2 else "ALTO",
                    "descripcion": f"Posible ataque de fuerza bruta detectado ({total} intentos en {args.minutos}m)"
                }
                alertas.append(alerta_data)
                
                msg_alerta = f"ALERTA [{alerta_data['nivel_riesgo']}]: {alerta_data['descripcion']} desde IP {ip}"
                print(f"{COLOR_RED}[CRÍTICO] {msg_alerta}{COLOR_RESET}")
                logging.warning(msg_alerta)

        if alertas:
            guardar_alertas_json(alertas, args.jsonfile)
            print(f"[*] {len(alertas)} alerta(s) guardada(s) en '{args.jsonfile}'.")

    except OperationalError as e:
        err_msg = f"Error de conexión a la base de datos (Host/Credenciales): {e}"
        print(f"{COLOR_RED}[ERROR]{COLOR_RESET} {err_msg}")
        logging.error(err_msg)
        sys.exit(1)
    except MySQLError as e:
        err_msg = f"Error en la ejecución SQL: {e}"
        print(f"{COLOR_RED}[ERROR]{COLOR_RESET} {err_msg}")
        logging.error(err_msg)
        sys.exit(2)
    finally:
        if conexion and conexion.open:
            conexion.close()

if __name__ == "__main__":
    procesar_auditoria()
