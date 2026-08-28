#!/usr/bin/env python3
import argparse
import mysql.connector
from datetime import datetime, timedelta

# Argumentos desde cron
parser = argparse.ArgumentParser()
parser.add_argument("--minutos", type=int, default=10)
parser.add_argument("--umbral", type=int, default=2)
args = parser.parse_args()

# Conexión a MariaDB
conn = mysql.connector.connect(
    host="localhost",
    user="python_user",
    password="Tu pasword",
    database="seguridad"
)
cursor = conn.cursor()

# Calcular ventana de tiempo
tiempo_limite = datetime.now() - timedelta(minutes=args.minutos)

# Buscar intentos fallidos recientes
cursor.execute("""
    SELECT usuario, ip, fecha
    FROM accesos
    WHERE resultado = 'fallido' AND fecha >= %s
""", (tiempo_limite.strftime("%Y-%m-%d %H:%M:%S"),))

fallidos = cursor.fetchall()

print("=== INICIANDO PROCESAMIENTO DE AUDITORÍA ===")
print(f"[*] Inspeccionando eventos de los últimos {args.minutos} minutos...")

if not fallidos:
    print("[*] Sin intentos fallidos detectados en el periodo especificado.")
else:
    sospechosos = {}
    for usuario, ip, fecha in fallidos:
        sospechosos[ip] = sospechosos.get(ip, 0) + 1

    for ip, cantidad in sospechosos.items():
        if cantidad >= args.umbral:
            print(f"[!] ALERTA: La IP {ip} tuvo {cantidad} intentos fallidos recientes.")

cursor.close()
conn.close()
