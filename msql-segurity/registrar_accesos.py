import mysql.connector
import re

# Conexión a MariaDB con usuario seguro
conn = mysql.connector.connect(
    host="localhost",
    user="python_user",
    password="Tu password",   # la contraseña que definiste
    database="seguridad"
)
cursor = conn.cursor()

# Leer el archivo de logs del sistema
with open("/var/log/auth.log", "r") as f:
    for line in f:
        if "Failed password" in line:
            match = re.search(r'for (\w+) from ([\d\.]+)', line)
            if match:
                usuario = match.group(1)
                ip = match.group(2)
                resultado = "fallido"

                cursor.execute(
                    "INSERT INTO accesos (usuario, ip, resultado) VALUES (%s, %s, %s)",
                    (usuario, ip, resultado)
                )

conn.commit()
cursor.close()
conn.close()
