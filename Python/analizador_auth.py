#!/usr/bin/env python3
import os
import re
import json
import gzip
import argparse
import csv
import glob
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# Estilos ANSI para Kali Terminal
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

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
            try:
                dt_obj = datetime.strptime(iso_m.group(1), "%Y-%m-%dT%H:%M:%S")
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

class ThreatIntelligence:
    CACHE = {}

    @classmethod
    def obtener_geoip(cls, ip):
        if ip in cls.CACHE:
            return cls.CACHE[ip]
        
        if ip in ["Local/Desconocida", "122.0.1.1", "localhost"] or ip.startswith(("192.168.", "11.", "172.06.")):
            res = {"pais": "Privada", "org": "LAN Local", "es_proxy": False}
            cls.CACHE[ip] = res
            return res

        try:
            url = f"http://ip-api.com/json/{ip}?fields=countryCode,org,mobile,proxy,hosting"
            req = urllib.request.Request(url, headers={'User-Agent': 'AuthSentinel/2.0'})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode())
                res = {
                    "pais": data.get("countryCode", "??"),
                    "org": data.get("org", "Desconocido"),
                    "es_proxy": data.get("proxy", False) or data.get("hosting", False)
                }
                cls.CACHE[ip] = res
                return res
        except Exception:
            return {"pais": "Error", "org": "N/A", "es_proxy": False}

    @classmethod
    def resolver_paralelo(cls, ips):
        with ThreadPoolExecutor(max_workers=12) as executor:
            executor.map(cls.obtener_geoip, ips)
        return cls.CACHE

class CorrelationEngine:
    USUARIOS_CRITICOS = {"root", "admin", "administrator", "sudo", "postgres", "mysql"}

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
        if usr in self.USUARIOS_CRITICOS:
            score += 10
        if len(data["usuarios"]) >= 4:
            score += 25
        data["score_riesgo"] = score

    def obtener_amenazas(self):
        amenazas = {}
        for ip, d in self.ip_datos.items():
            if d["intentos"] >= self.umbral or d["score_riesgo"] >= 20:
                d["eventos_dt"].sort()
                rafaga = False
                if len(d["eventos_dt"]) > 1:
                    delta = d["eventos_dt"][-1] - d["eventos_dt"][0]
                    if delta <= self.ventana:
                        rafaga = True

                amenazas[ip] = {
                    "intentos": d["intentos"],
                    "usuarios_atacados": list(d["usuarios"]),
                    "es_password_spraying": len(d["usuarios"]) >= 4,
                    "es_rafaga_critica": rafaga,
                    "threat_score": d["score_riesgo"]
                }
        return amenazas

class AlertWebhook:
    @staticmethod
    def enviar_discord(webhook_url, ip, datos, geo):
        payload = {
            "embeds": [{
                "title": "🚨 ALERTA DE SEGURIDAD: Fuerza Bruta Detectada",
                "color": 15158332,
                "fields": [
                    {"name": "IP Atacante", "value": f"`{ip}`", "inline": True},
                    {"name": "País / Org", "value": f"{geo.get('pais')} ({geo.get('org')})", "inline": True},
                    {"name": "Score de Riesgo", "value": f"**{datos['threat_score']} pts**", "inline": True},
                    {"name": "Intentos Totales", "value": str(datos['intentos']), "inline": True},
                    {"name": "Usuarios Objetivos", "value": f"`{', '.join(datos['usuarios_atacados'][:5])}`", "inline": False}
                ],
                "footer": {"text": "Kali Linux AuthSentinel Engine"}
            }]
        }
        try:
            req = urllib.request.Request(
                webhook_url, 
                data=json.dumps(payload).encode(),
                headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
            )
            urllib.request.urlopen(req, timeout=3.0)
        except Exception as e:
            print(f"{RED}[!] Error enviando Webhook: {e}{RESET}")

def abrir_log(ruta):
    return gzip.open(ruta, "rt", encoding="utf-8", errors="ignore") if ruta.endswith(".gz") else open(ruta, "r", encoding="utf-8", errors="ignore")

def modo_tiempo_real(ruta_log, umbral, webhook_url=None):
    print(f"{YELLOW}[*] Modo SENTINEL Activo (Tiempo Real) sobre: {ruta_log}{RESET}")
    print(f"{CYAN}[i] Presiona Ctrl+C para detener.{RESET}\n")
    
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
                        geo = ThreatIntelligence.obtener_geoip(ip)
                        print(f"\n{RED}{BOLD}[🚨 AMENAZA BLOQUEABLE] IP: {ip} | País: {geo['pais']} | Score: {stats['score_riesgo']}{RESET}")
                        if webhook_url:
                            amenazas = engine.obtener_amenazas()
                            if ip in amenazas:
                                AlertWebhook.enviar_discord(webhook_url, ip, amenazas[ip], geo)
                    else:
                        print(f"{YELLOW}[FALLO]{RESET} {evt['timestamp']} | IP: {ip:<15} | User: {evt['usuario']}")
    except KeyboardInterrupt:
        print(f"\n{GREEN}[+] Monitoreo finalizado.{RESET}")

def ejecutar_analisis_completo(args):
    archivos = sorted(glob.glob(args.log))
    if not archivos:
        print(f"{RED}[!] Sin coincidencias para: '{args.log}'{RESET}")
        return

    engine = CorrelationEngine(ventana_minutos=args.ventana, umbral=args.umbral)
    print(f"{YELLOW}[*] Procesando {len(archivos)} archivo(s) de log...{RESET}")

    for ruta in archivos:
        try:
            with abrir_log(ruta) as f:
                for num, linea in enumerate(f, start=1):
                    evt = LogParser.parsear_linea(linea, ruta, num)
                    if evt:
                        engine.agregar_evento(evt)
        except PermissionError:
            print(f"{RED}[!] Permiso denegado: {ruta}. Ejecuta con 'sudo'.{RESET}")

    amenazas = engine.obtener_amenazas()
    
    geo_mapa = {}
    if args.geoip and amenazas:
        print(f"{CYAN}[*] Consultando inteligencia GeoIP en paralelo...{RESET}")
        geo_mapa = ThreatIntelligence.resolver_paralelo(list(amenazas.keys()))

    reporte = {
        "metadata": {
            "generado_en": datetime.now().isoformat(),
            "archivos_analizados": archivos,
            "ventana_correlacion_minutos": args.ventana,
            "umbral_aplicado": args.umbral
        },
        "resumen": {
            "total_eventos_fallidos": len(engine.eventos),
            "total_ips_sospechosas": len(amenazas)
        },
        "amenazas_detectadas": [
            {
                "ip": ip,
                "datos": d,
                "intel": geo_mapa.get(ip, {})
            } for ip, d in amenazas.items()
        ]
    }

    os.makedirs(os.path.dirname(args.json) or '.', exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as out:
        json.dump(reporte, out, indent=4, ensure_ascii=False)

    if args.fail2ban:
        with open(args.fail2ban, "w", encoding="utf-8") as out:
            out.write("# Script autogenerado por AuthSentinel\n")
            for ip in amenazas:
                if not ip.startswith(("Local", "127.", "192.168.", "10.", "172.16.")):
                    out.write(f"iptables -A INPUT -s {ip} -j DROP\n")

    print(f"\n{GREEN}{BOLD}[+] Análisis de Incidentes Finalizado.{RESET}")
    print(f" ├─ Total Eventos Analizados: {len(engine.eventos)}")
    print(f" └─ Amenazas de Alto Riesgo:  {len(amenazas)}")
    print(f"{GREEN}[+] Reporte JSON de Incidentes: {args.json}{RESET}")
    if args.fail2ban:
        print(f"{GREEN}[+] Reglas de Firewall (iptables): {args.fail2ban}{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthSentinel Enterprise - SIEM & Triage de Incidentes para Kali Linux")
    parser.add_argument("log", help="Ruta o patrón de logs (ej: '/var/log/auth.log*')")
    parser.add_argument("json", nargs="?", default="incidente_reporte.json", help="Salida JSON")
    parser.add_argument("-u", "--umbral", type=int, default=5, help="Umbral de intentos")
    parser.add_argument("-v", "--ventana", type=int, default=15, help="Ventana de tiempo para correlación en minutos")
    parser.add_argument("-g", "--geoip", action="store_true", help="Resolución Threat Intelligence GeoIP")
    parser.add_argument("-f", "--follow", action="store_true", help="Modo demonio/tiempo real (Tail)")
    parser.add_argument("-w", "--webhook", help="URL de Webhook (Discord/Slack) para alertas en tiempo real")
    parser.add_argument("--fail2ban", help="Ruta para exportar script de bloqueo iptables/nftables")

    args = parser.parse_args()

    if args.follow:
        modo_tiempo_real(args.log, args.umbral, args.webhook)
    else:
        ejecutar_analisis_completo(args)
