#!/usr/bin/env python3
import os
import re
import json
import gzip
import argparse
import glob
import time
import urllib.request
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# Configuración de logs
log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "auditoria.log")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# También mostrar en consola
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

class LogParser:
    PATRON_FALLO = re.compile(
        r"(Failed password|Authentication failure|Failed keyboard-interactive|invalid user|PAM \d+ more authentication failures|Accepted password)", 
        re.IGNORECASE
    )
    PATRON_IP = re.compile(r"(?:rhost=|from\s+|client\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
    PATRON_USUARIO = re.compile(r"(?:for\s+(?:invalid\s+user\s+)?|user=|\bfor\b\s+)(\S+)", re.IGNORECASE)
    PATRON_FECHA_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
    PATRON_FECHA_BSD = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")

    @classmethod
    def parsear_linea(cls, linea, archivo="stream", num_linea=0):
        if not cls.PATRON_FALLO.search(linea):
            return None
        es_exito = "Accepted password" in linea
        ip_m = cls.PATRON_IP.search(linea)
        usr_m = cls.PATRON_USUARIO.search(linea)
        ip = ip_m.group(1) if ip_m else "Local/Desconocida"
        usr = usr_m.group(1) if usr_m else "Desconocido"
        dt_obj = datetime.now()
        iso_m = cls.PATRON_FECHA_ISO.search(linea)
        bsd_m = cls.PATRON_FECHA_BSD.search(linea)
        if iso_m:
            try: dt_obj = datetime.strptime(iso_m.group(1), "%Y-%m-%dT%H:%M:%S")
            except ValueError: pass
        elif bsd_m:
            try:
                fch_str = f"{datetime.now().year} {bsd_m.group(1)}"
                dt_obj = datetime.strptime(fch_str, "%Y %b %d %H:%M:%S")
            except ValueError: pass
        return {
            "archivo": os.path.basename(archivo),
            "linea": num_linea,
            "timestamp_dt": dt_obj,
            "timestamp": dt_obj.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "usuario": usr,
            "es_exito": es_exito,
            "registro": linea.strip()
        }

class CorrelationEngine:
    def __init__(self, ventana_minutos=15, umbral=5):
        self.ventana = timedelta(minutes=ventana_minutos)
        self.umbral = umbral
        self.eventos = []
        self.ip_datos = {}

    def agregar_evento(self, evt):
        if not evt or evt["es_exito"]: 
            return
        self.eventos.append(evt)
        ip = evt["ip"]
        usr = evt["usuario"]
        if ip not in self.ip_datos:
            self.ip_datos[ip] = {
                "intentos": 0,
                "usuarios": set(),
                "eventos_dt": [],
                "score_riesgo": 0
            }
        data = self.ip_datos[ip]
        data["intentos"] += 1
        data["usuarios"].add(usr)
        data["eventos_dt"].append(evt["timestamp_dt"])
        score = data["intentos"] * 2
        if usr in {"root","admin","administrator","sudo","postgres","mysql"}:
            score += 10
        if len(data["usuarios"]) >= 4:
            score += 25
        data["score_riesgo"] = score

    def obtener_amenazas(self):
        amenazas = {}
        for ip, d in self.ip_datos.items():
            if d["intentos"] >= self.umbral or d["score_riesgo"] >= 20:
                amenazas[ip] = {
                    "intentos": d["intentos"],
                    "usuarios_atacados": list(d["usuarios"]),
                    "threat_score": d["score_riesgo"]
                }
        return amenazas

def abrir_log(ruta):
    return gzip.open(ruta, "rt", encoding="utf-8", errors="ignore") if ruta.endswith(".gz") else open(ruta, "r", encoding="utf-8", errors="ignore")

def modo_tiempo_real(ruta_log, umbral):
    logging.info(f"[*] Modo SENTINEL Activo (Tiempo Real) sobre: {ruta_log}")
    engine = CorrelationEngine(umbral=umbral)
    try:
        with abrir_log(ruta_log) as f:
            f.seek(0, os.SEEK_END)
            while True:
                linea = f.readline()
                if not linea:
                    time.sleep(0.3)
                    continue
                evt = LogParser.parsear_linea(linea, ruta_log)
                if evt:
                    engine.agregar_evento(evt)
                    ip = evt['ip']
                    stats = engine.ip_datos[ip]
                    if stats['intentos'] == umbral:
                        logging.error(f"[🚨 AMENAZA BLOQUEABLE] IP: {ip} | Score: {stats['score_riesgo']}")
                    else:
                        logging.warning(f"[FALLO] {evt['timestamp']} | IP: {ip:<15} | User: {evt['usuario']}")
    except KeyboardInterrupt:
        logging.info("[+] Monitoreo finalizado.")

def ejecutar_analisis_completo(args):
    archivos = sorted(glob.glob(args.log))
    if not archivos:
        logging.error(f"[!] Sin coincidencias para: '{args.log}'")
        return
    engine = CorrelationEngine(ventana_minutos=args.ventana, umbral=args.umbral)
    logging.info(f"[*] Procesando {len(archivos)} archivo(s) de log...")
    for ruta in archivos:
        try:
            with abrir_log(ruta) as f:
                for num, linea in enumerate(f, start=1):
                    evt = LogParser.parsear_linea(linea, ruta, num)
                    if evt: engine.agregar_evento(evt)
        except PermissionError:
            logging.error(f"[!] Permiso denegado: {ruta}. Ejecuta con 'sudo'.")
    amenazas = engine.obtener_amenazas()
    logging.info(f"[+] Análisis de Incidentes Finalizado. Total Eventos: {len(engine.eventos)} | Amenazas: {len(amenazas)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthSentinel Python - Auditoría de autenticación")
    parser.add_argument("log", help="Ruta o patrón de logs (ej: '/var/log/auth.log*')")
    parser.add_argument("-u", "--umbral", type=int, default=5, help="Umbral de intentos")
    parser.add_argument("-v", "--ventana", type=int, default=15, help="Ventana de tiempo para correlación en minutos")
    parser.add_argument("-f", "--follow", action="store_true", help="Modo tiempo real (Tail)")
    args = parser.parse_args()
    if args.follow:
        modo_tiempo_real(args.log, args.umbral)
    else:
        ejecutar_analisis_completo(args)
