import mysql.connector
from datetime import datetime
import os

# 1. Conexión a MariaDB con usuario seguro
conn = mysql.connector.connect(
    host="localhost",
    user="python_user",
    password="ClaveSegura123",   # asegúrate de usar la contraseña correcta
    database="seguridad"
)
cursor = conn.cursor()

# 2. Crear carpeta por fecha (ej. reportes/2026-08-27)
fecha_actual = datetime.now()
fecha_carpeta = fecha_actual.strftime("%Y-%m-%d")
ruta_carpeta = f"reportes/{fecha_carpeta}"

# Si la carpeta no existe, se crea automáticamente
os.makedirs(ruta_carpeta, exist_ok=True)

# 3. Nombre dinámico para el archivo Markdown (ej. informe_02-20-00.md)
nombre_archivo = f"{ruta_carpeta}/informe_{fecha_actual.strftime('%H-%M-%S')}.md"

# 4. Generar el informe en formato Markdown
with open(nombre_archivo, "w") as f:
    f.write(f"# Informe Forense de Accesos\n")
    f.write(f"Generado en: {fecha_actual}\n\n")

    # 📊 Ranking de IPs sospechosas
    cursor.execute("""
        SELECT ip, COUNT(*) AS intentos
        FROM accesos
        WHERE resultado = 'fallido'
        GROUP BY ip
        ORDER BY intentos DESC
        LIMIT 10;
    """)
    f.write("## 📊 Ranking de IPs sospechosas\n\n")
    f.write("| IP | Intentos fallidos |\n")
    f.write("|----|-------------------|\n")
    for row in cursor.fetchall():
        f.write(f"| {row[0]} | {row[1]} |\n")

    f.write("\n")

    # 👤 Usuarios más atacados
    cursor.execute("""
        SELECT usuario, COUNT(*) AS intentos
        FROM accesos
        WHERE resultado = 'fallido'
        GROUP BY usuario
        ORDER BY intentos DESC;
    """)
    f.write("## 👤 Usuarios más atacados\n\n")
    f.write("| Usuario | Intentos fallidos |\n")
    f.write("|---------|-------------------|\n")
    for row in cursor.fetchall():
        f.write(f"| {row[0]} | {row[1]} |\n")

cursor.close()
conn.close()
