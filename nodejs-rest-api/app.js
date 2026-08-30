const express = require('express');
const basicAuth = require('express-basic-auth');
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());

// Pool de conexión a la base de datos MySQL
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Función para registrar logs locales en /logs/api_access.log
const logEvent = (mensaje) => {
  const logPath = path.join(__dirname, 'logs', 'api_access.log');
  const timestamp = new Date().toISOString();
  fs.appendFileSync(logPath, `[${timestamp}] ${mensaje}\n`);
};

// Middleware de Autenticación Básica HTTP
const auth = basicAuth({
  users: { [process.env.API_USER]: process.env.API_PASS },
  unauthorizedResponse: (req) => {
    logEvent(`ACCESO RECHAZADO: Credenciales inválidas desde IP ${req.ip}`);
    return { error: 'Acceso no autorizado' };
  }
});

// Endpoint protegido para registrar eventos en MySQL
app.post('/api/v1/registro', auth, async (req, res) => {
  const { usuario, ip_origen, estado } = req.body;
  
  try {
    const query = 'INSERT INTO registros_acceso (usuario, ip_origen, estado, fecha) VALUES (?, ?, ?, NOW())';
    await db.execute(query, [usuario, ip_origen, estado]);
    
    logEvent(`ÉXITO: Registro insertado para usuario '${usuario}' desde ${ip_origen}`);
    res.status(201).json({ status: 'ok', message: 'Acceso registrado en MySQL' });
  } catch (err) {
    logEvent(`ERROR DB: ${err.message}`);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logEvent(`Servidor iniciado en puerto ${PORT}`);
  console.log(`Servidor API escuchando en el puerto ${PORT}`);
});
