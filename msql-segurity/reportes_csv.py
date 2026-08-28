import mysql.connector
import csv
from datetime import datetime

# Conexión a MariaDB
conn = mysql.connector.connect(
    host="localhost",
    user="python_user",
    password="ClaveSegura123",
    database="seguridad"
)
cursor = conn.cursor()

# Nombre dinámico para el archivo CSV
fecha_actual = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
nombre_archivo = f"informe_{fecha_actual}.csv"

with open(nombre_archivo, "w", newline="") as f:
    writer = csv.writer(f)
    
    # Ranking de IPs sospechosas
    cursor.execute("""
        SELECT ip, COUNT(*) AS intentos
        FROM accesos
        WHERE resultado = 'fallido'
        GROUP BY ip
        ORDER BY intentos DESC
        LIMIT 10;
    """)
    writer.writerow(["📊 Ranking de IPs sospechosas"])
    writer.writerow(["IP", "Intentos fallidos"])
    for row in cursor.fetchall():
        writer.writerow(row)

    writer.writerow([])

    # Usuarios más atacados
    cursor.execute("""
        SELECT usuario, COUNT(*) AS intentos
        FROM accesos
        WHERE resultado = 'fallido'
        GROUP BY usuario
        ORDER BY intentos DESC;
    """)
    writer.writerow(["👤 Usuarios más atacados"])
    writer.writerow(["Usuario", "Intentos fallidos"])
    for row in cursor.fetchall():
        writer.writerow(row)

cursor.close()
conn.close()
