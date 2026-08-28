import mysql.connector
from datetime import datetime

# Conexión a MariaDB con usuario seguro
conn = mysql.connector.connect(
    host="localhost",
    user="python_user",
    password="ClaveSegura123",
    database="seguridad"
)
cursor = conn.cursor()

# Generar timestamp y nombre de archivo dinámico
fecha_actual = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
nombre_archivo = f"informe_{fecha_actual}.txt"

with open(nombre_archivo, "w") as f:
    f.write("=== Informe Forense de Accesos ===\n")
    f.write(f"Generado en: {fecha_actual}\n\n")

    # Ranking de IPs sospechosas
    cursor.execute("""
        SELECT ip, COUNT(*) AS intentos
        FROM accesos
        WHERE resultado = 'fallido'
        GROUP BY ip
        ORDER BY intentos DESC
        LIMIT 10;
    """)
    f.write("📊 Ranking de IPs sospechosas:\n")
    for row in cursor.fetchall():
        f.write(f"IP: {row[0]} - Intentos fallidos: {row[1]}\n")

    f.write("\n")

    # Usuarios más atacados
    cursor.execute("""
        SELECT usuario, COUNT(*) AS intentos
        FROM accesos
        WHERE resultado = 'fallido'
        GROUP BY usuario
        ORDER BY intentos DESC;
    """)
    f.write("👤 Usuarios más atacados:\n")
    for row in cursor.fetchall():
        f.write(f"Usuario: {row[0]} - Intentos fallidos: {row[1]}\n")

cursor.close()
conn.close()
