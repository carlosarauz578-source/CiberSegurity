import asyncio
import json
import os
import re
import subprocess
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastapi import BackgroundTasks, FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse
import httpx
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import uvicorn

NUCLEI_TEMPLATES = os.getenv("NUCLEI_TEMPLATES_PATH", "/usr/share/nuclei-templates")

DATABASE_URL = "sqlite:///./audit_history.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AuditRecord(Base):
    __tablename__ = "ultra_ultimate_audits"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    status = Column(String)
    risk_score = Column(Integer)
    findings_count = Column(Integer)
    logs = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Container Vuln Engine - Ethical Hacking & Remediation Edition", version="11.1")

scan_status = {"status": "Inactivo", "risk_score": 0, "logs": []}
scan_lock = asyncio.Lock()

def get_remediation_and_legal_advice(finding_source: str, detail: str) -> dict:
    """Proporciona directrices de remediación técnica y marco legal aplicable a cada hallazgo."""
    lower_detail = detail.lower()
    if "sql" in lower_detail or finding_source == "SQLMAP":
        return {
            "remediation": "Utilizar consultas parametrizadas (Prepared Statements), ORMs seguros y validación estricta de tipos de entrada en formularios y APIs.",
            "legal_framework": "Ley de Protección de Datos Personales (Privacidad de la Información) y normativas de seguridad en bases de datos (OWASP Top 10 A03 - Injection)."
        }
    elif "exec" in lower_detail or "rce" in lower_detail:
        return {
            "remediation": "Eliminar funciones de ejecución directa del sistema operativo (system, eval, shell_exec). Implementar listas blancas estrictas para parámetros de entrada.",
            "legal_framework": "Leyes de Delitos Informáticos, Acceso Ilegítimo a Sistemas y Convención de Budapest sobre Ciberdelincuencia."
        }
    elif "fi" in lower_detail or "lfi" in lower_detail:
        return {
            "remediation": "Deshabilitar el acceso remoto a archivos en la configuración del lenguaje (ej. allow_url_include=Off) y usar mapeos estáticos de rutas permitidas.",
            "legal_framework": "Auditorías de cumplimiento normativo, ISO/IEC 27001 (Control de Acceso a Ficheros Sensibles)."
        }
    elif "brute" in lower_detail or "login" in lower_detail:
        return {
            "remediation": "Implementar autenticación multifactor (MFA), bloqueo automático de cuentas por intentos fallidos y políticas robustas de contraseñas.",
            "legal_framework": "Estándares de gestión de accesos y autenticación corporativa (ISO/IEC 27001 / NIST SP 800-63)."
        }
    elif "privileged" in lower_detail or finding_source == "INSPECT":
        return {
            "remediation": "Ejecutar contenedores con privilegios mínimos (rootless mode, drop capabilities, --security-opt). Nunca usar el flag --privileged en producción.",
            "legal_framework": "Buenas prácticas de hardening de contenedores y normativas de seguridad en infraestructura cloud (CIS Benchmarks / NIST SP 800-190)."
        }
    else:
        return {
            "remediation": "Aplicar parches de actualización de software, realizar análisis estáticos de dependencias y mitigar vulnerabilidades conocidas (CVE).",
            "legal_framework": "Responsabilidad civil y corporativa por negligencia en la gestión de vulnerabilidades y parches de seguridad."
        }

def get_running_containers():
    runtimes = [
        ["podman", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Ports}}"],
        ["docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Ports}}"],
        ["nerdctl", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Ports}}"]
    ]
    for cmd in runtimes:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            containers = []
            for line in result.stdout.splitlines():
                if line.strip():
                    parts = line.split("|")
                    if len(parts) >= 3:
                        name, image, ports = parts[0], parts[1], parts[2]
                        match = re.search(r'(?:0\.0\.0\.0|127\.0\.0\.1|::):(\d+)->', ports)
                        if not match:
                            match = re.search(r':(\d+)->', ports)
                        port = match.group(1) if match else "80"
                        target_url = f"http://127.0.0.1:{port}" if port != "80" else "http://127.0.0.1"
                        containers.append({"name": f"{cmd[0]}:{name}", "image": image, "url": target_url, "ports": ports})
            if containers:
                return containers
        except Exception:
            continue
    return []

async def run_nmap_deep(target_host: str, findings: list):
    try:
        clean_host = target_host.replace("http://", "").replace("https://", "").split(":")[0]
        scan_status["logs"].append(f"[RECON] Nmap escaneando puertos en {clean_host}...")
        process = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-T4", clean_host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        if stdout:
            for line in stdout.decode().splitlines():
                if "open" in line or "service" in line:
                    detail_str = line.strip()
                    advice = get_remediation_and_legal_advice("NMAP", detail_str)
                    log_line = f"[NMAP] {detail_str} | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                    scan_status["logs"].append(log_line)
                    findings.append({"source": "NMAP", "severity": "LOW", "detail": detail_str, "remediation": advice["remediation"], "legal": advice["legal_framework"]})
    except Exception as e:
        scan_status["logs"].append(f"[RECON] Nmap omitido: {str(e)}")

async def run_ffuf_fuzzing(target_url: str, findings: list):
    wordlist_path = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist_path):
        wordlist_path = "/tmp/fuzz.txt"
        with open(wordlist_path, "w") as f:
            f.write("admin\nlogin\nconfig\nbackup\napi\nsecret\ndb\nsetup.php\nindex.php\n")
    try:
        scan_status["logs"].append(f"[FUZZING] FFUF descubriendo rutas en {target_url}...")
        process = await asyncio.create_subprocess_exec(
            "ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist_path, "-fc", "404,403", "-s",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        if stdout:
            for line in stdout.decode().splitlines():
                if line.strip():
                    detail_str = f"Ruta expuesta: {line.strip()}"
                    advice = get_remediation_and_legal_advice("FFUF", detail_str)
                    log_line = f"[FFUF] {detail_str} | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                    scan_status["logs"].append(log_line)
                    findings.append({"source": "FFUF", "severity": "MEDIUM", "detail": detail_str, "remediation": advice["remediation"], "legal": advice["legal_framework"]})
    except Exception as e:
        scan_status["logs"].append(f"[FUZZING] FFUF omitido: {str(e)}")

async def run_sqlmap_audit(target_url: str, findings: list):
    try:
        test_url = f"{target_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
        scan_status["logs"].append(f"[SQLMAP] Analizando inyecciones SQL...")
        process = await asyncio.create_subprocess_exec(
            "sqlmap", "-u", test_url, "--batch", "--level=1", "--risk=1", "--smart", "--threads=2",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=30)
        if stdout and ("is vulnerable" in stdout.decode() or "injectable" in stdout.decode()):
            advice = get_remediation_and_legal_advice("SQLMAP", "SQL Injection detected")
            log_line = f"[SQLMAP] [CRITICAL] ¡Inyección SQL confirmada! | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
            scan_status["logs"].append(log_line)
            findings.append({"source": "SQLMAP", "severity": "CRITICAL", "detail": "SQL Injection detected", "remediation": advice["remediation"], "legal": advice["legal_framework"]})
    except Exception:
        pass

async def run_logic_modules_exploit(target_url: str, findings: list):
    scan_status["logs"].append("[LOGIC MODULES] Iniciando pruebas funcionales de módulos de aplicación...")
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
        try:
            cmd_url = f"{target_url}/vulnerabilities/exec/"
            resp = await client.post(cmd_url, data={"ip": "127.0.0.1; id", "Submit": "Submit"})
            if resp.status_code == 200 and ("uid=" in resp.text or "gid=" in resp.text):
                advice = get_remediation_and_legal_advice("LOGIC_EXEC", "Command Injection RCE confirmed")
                log_line = f"[LOGIC MODULES] [CRITICAL] RCE confirmado. | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                scan_status["logs"].append(log_line)
                findings.append({"source": "LOGIC_EXEC", "severity": "CRITICAL", "detail": "Command Injection RCE confirmed", "remediation": advice["remediation"], "legal": advice["legal_framework"]})
            
            resp_lfi = await client.get(f"{target_url}/vulnerabilities/fi/?page=/etc/passwd")
            if resp_lfi.status_code == 200 and "root:x:" in resp_lfi.text:
                advice = get_remediation_and_legal_advice("LOGIC_LFI", "Local File Inclusion exposed /etc/passwd")
                log_line = f"[LOGIC MODULES] [HIGH] LFI expuso /etc/passwd. | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                scan_status["logs"].append(log_line)
                findings.append({"source": "LOGIC_LFI", "severity": "HIGH", "detail": "Local File Inclusion exposed /etc/passwd", "remediation": advice["remediation"], "legal": advice["legal_framework"]})
                
            login_url = f"{target_url}/login.php"
            resp_login = await client.post(login_url, data={"username": "admin", "password": "password", "Login": "Login"})
            if resp_login.status_code == 200 and ("Welcome" in resp_login.text or "logout" in resp_login.text.lower()):
                advice = get_remediation_and_legal_advice("LOGIC_BRUTE", "Default credentials active")
                log_line = f"[LOGIC MODULES] [MEDIUM] Credenciales por defecto activas. | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                scan_status["logs"].append(log_line)
                findings.append({"source": "LOGIC_BRUTE", "severity": "MEDIUM", "detail": "Default credentials active", "remediation": advice["remediation"], "legal": advice["legal_framework"]})
        except Exception as e:
            scan_status["logs"].append(f"[LOGIC MODULES] Nota de ejecución: {str(e)}")

async def run_container_inspect(target_name: str, findings: list):
    if ":" not in target_name:
        return
    runtime, c_name = target_name.split(":", 1)
    try:
        scan_status["logs"].append(f"[INSPECT] Evaluando privilegios de aislamiento del contenedor {c_name}...")
        process = await asyncio.create_subprocess_exec(
            runtime, "inspect", c_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        if stdout:
            inspect_data = json.loads(stdout.decode())[0]
            if inspect_data.get("HostConfig", {}).get("Privileged", False):
                advice = get_remediation_and_legal_advice("INSPECT", "Privileged container")
                log_line = f"[INSPECT] [CRITICAL] Contenedor PRIVILEGIADO. | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                scan_status["logs"].append(log_line)
                findings.append({"source": "INSPECT", "severity": "CRITICAL", "detail": "Privileged container", "remediation": advice["remediation"], "legal": advice["legal_framework"]})
    except Exception:
        pass

async def run_syft_sbom(target_image: str, findings: list):
    try:
        scan_status["logs"].append(f"[SYFT] Generando SBOM para {target_image}...")
        process = await asyncio.create_subprocess_exec(
            "syft", target_image, "-o", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        if stdout:
            count = len(json.loads(stdout.decode().strip()).get("artifacts", []))
            advice = get_remediation_and_legal_advice("SYFT", f"SBOM assets: {count}")
            log_line = f"[SYFT] SBOM generado con {count} artefactos. | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
            scan_status["logs"].append(log_line)
            findings.append({"source": "SYFT", "severity": "LOW", "detail": f"SBOM assets: {count}", "remediation": advice["remediation"], "legal": advice["legal_framework"]})
    except Exception:
        pass

async def execute_nuclei(target: str, findings: list):
    try:
        process = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target, "-t", NUCLEI_TEMPLATES, "-json", "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            try:
                data = json.loads(line.decode().strip())
                sev = data.get("info", {}).get("severity", "info").upper()
                template_id = data.get('template-id')
                advice = get_remediation_and_legal_advice("NUCLEI", template_id)
                log_line = f"[NUCLEI] [{sev}] {template_id} | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                scan_status["logs"].append(log_line)
                findings.append({"source": "NUCLEI", "severity": sev, "detail": template_id, "remediation": advice["remediation"], "legal": advice["legal_framework"]})
            except Exception:
                continue
        await process.wait()
    except Exception:
        pass

async def execute_trivy(target_image: str, findings: list):
    try:
        scan_status["logs"].append(f"[TRIVY] Analizando vulnerabilidades estáticas de la imagen...")
        process = await asyncio.create_subprocess_exec(
            "trivy", "image", "--quiet", "--format", "json", target_image,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        if stdout:
            for rg in json.loads(stdout.decode().strip()).get("Results", []):
                for vuln in rg.get("Vulnerabilities", []):
                    sev = vuln.get("Severity", "UNKNOWN").upper()
                    vuln_id = vuln.get('VulnerabilityID')
                    advice = get_remediation_and_legal_advice("TRIVY", vuln_id)
                    log_line = f"[TRIVY] [{sev}] {vuln_id} | [SOLUCIÓN] {advice['remediation']} | [LEGAL] {advice['legal_framework']}"
                    scan_status["logs"].append(log_line)
                    findings.append({"source": "TRIVY", "severity": sev, "detail": vuln_id, "remediation": advice["remediation"], "legal": advice["legal_framework"]})
    except Exception:
        pass

async def run_ultra_ultimate_audit(target_url: str, container_fullName: str, container_image: str):
    global scan_status
    if scan_lock.locked():
        return

    async with scan_lock:
        scan_status["status"] = f"Auditoría Ética en Progreso: {target_url}"
        scan_status["risk_score"] = 0
        scan_status["logs"].clear()
        scan_status["logs"].append(f"[INICIO] Auditoría de Hacking Ético con Leyes y Soluciones activada contra: {target_url}")
        
        findings = []
        
        await asyncio.gather(
            run_nmap_deep(target_url, findings),
            run_ffuf_fuzzing(target_url, findings),
            run_sqlmap_audit(target_url, findings),
            run_logic_modules_exploit(target_url, findings),
            run_container_inspect(container_fullName, findings),
            run_syft_sbom(container_image, findings),
            execute_nuclei(target_url, findings),
            execute_trivy(container_image, findings)
        )
        
        weights = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3, "UNKNOWN": 1}
        score = sum(weights.get(f["severity"], 1) for f in findings)
        scan_status["risk_score"] = min(score, 100)
        
        scan_status["status"] = f"Auditoría Completada (Riesgo: {scan_status['risk_score']}/100)"
        scan_status["logs"].append(f"[FIN] Hallazgos totales: {len(findings)}. Riesgo global: {scan_status['risk_score']}/100. Registro con leyes y soluciones guardado en BD.")
        
        try:
            db = SessionLocal()
            db_record = AuditRecord(
                target=target_url,
                status=scan_status["status"],
                risk_score=scan_status["risk_score"],
                findings_count=len(findings),
                logs=json.dumps(findings, ensure_ascii=False)  # Guarda la lista estructurada con soporte UTF-8 completo
            )
            db.add(db_record)
            db.commit()
            db.close()
        except Exception as e:
            scan_status["logs"].append(f"[DB ERROR] Error guardando en base de datos: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    containers = get_running_containers()
    options_html = ""
    if containers:
        for c in containers:
            val = f"{c['url']}|{c['name']}|{c['image']}"
            options_html += f'<option value="{val}">Runtime: {c["name"]} (Img: {c["image"]}) [{c["url"]}]</option>'
    else:
        options_html = '<option value="http://127.0.0.1|local|alpine">http://127.0.0.1 (Fallback Local)</option>'

    logs_joined = "<br>".join(scan_status['logs']) if scan_status['logs'] else 'Seleccione un contenedor para iniciar la auditoría de hacking ético con leyes y soluciones...'
    
    return f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Container Vuln Engine - Ethical Hacking & Remediation</title>
        <style>
            body {{ font-family: 'Courier New', monospace; background: #020408; color: #39d353; padding: 25px; }}
            h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
            button {{ background: #238636; color: white; border: none; padding: 12px 24px; cursor: pointer; font-weight: bold; font-family: monospace; font-size: 14px; margin-top: 10px; margin-right: 10px; border-radius: 4px; }}
            button:hover {{ background: #2ea043; }}
            .btn-export {{ background: #1f6feb; }}
            .btn-export:hover {{ background: #388bfd; }}
            pre {{ background: #0d1117; padding: 15px; border: 1px solid #30363d; color: #8b949e; height: 380px; overflow-y: scroll; border-radius: 6px; }}
            .config-box {{ background: #161b22; padding: 20px; border: 1px solid #30363d; margin-bottom: 20px; width: 620px; border-radius: 6px; }}
            select, input {{ background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; padding: 10px; font-family: monospace; width: 100%; margin-top: 5px; margin-bottom: 15px; box-sizing: border-box; border-radius: 4px; }}
            label {{ font-size: 13px; color: #8b949e; font-weight: bold; }}
            .status-badge {{ color: #f0883e; font-weight: bold; }}
            .score-badge {{ color: #ff7b72; font-weight: bold; }}
        </style>
        <script>
            async function fetchStatus() {{
                const res = await fetch('/status-json');
                const data = await res.json();
                document.getElementById('engine-status').innerText = data.status;
                document.getElementById('risk-score').innerText = data.risk_score + '/100';
                document.getElementById('terminal-logs').innerHTML = data.logs.join('<br>');
            }}
            setInterval(fetchStatus, 2000);
        </script>
    </head>
    <body>
        <h1>🛡️ Container Vuln Engine [Hacking Ético, Leyes y Soluciones]</h1>
        <p>Estado del Motor: <span id="engine-status" class="status-badge">{scan_status['status']}</span> | Riesgo Global: <span id="risk-score" class="score-badge">{scan_status['risk_score']}/100</span></p>
        
        <form action="/start-audit" method="POST">
            <div class="config-box">
                <strong>Panel de Control con Análisis Legal y Remediación:</strong><br><br>
                <label for="target_combo">Contenedores Activos Detectados:</label>
                <select id="target_combo" name="target_combo">
                    {options_html}
                </select>
                
                <label for="custom_target">Objetivo URL Personalizado (Opcional):</label>
                <input type="text" id="custom_target" name="custom_target" placeholder="Ej: http://127.0.0.1:8080">
                
                <button type="submit">🚀 Iniciar Auditoría Completa</button>
                <a href="/export-report"><button type="button" class="btn-export">Exportar Reporte JSON Completo</button></a>
            </div>
        </form>
        
        <h3>Consola de Streaming en Vivo (Hallazgos, Soluciones y Leyes):</h3>
        <pre id="terminal-logs">{logs_joined}</pre>
    </body>
    </html>
    """

@app.post("/start-audit")
async def start_audit(background_tasks: BackgroundTasks, target_combo: str = Form(...), custom_target: str = Form(None)):
    if not scan_lock.locked():
        parts = target_combo.split("|")
        url_target = parts[0]
        c_name = parts[1] if len(parts) > 1 else "local"
        c_image = parts[2] if len(parts) > 2 else "alpine"

        final_url = custom_target.strip() if custom_target and custom_target.strip() else url_target
        background_tasks.add_task(run_ultra_ultimate_audit, final_url, c_name, c_image)
    return HTMLResponse(content="""<script>window.location.href = "/";</script>""")

@app.get("/status-json")
async def status_json():
    return JSONResponse(scan_status)

@app.get("/export-report")
async def export_report():
    db = SessionLocal()
    records = db.query(AuditRecord).all()
    db.close()
    
    historical_data = []
    for r in records:
        parsed_logs = r.logs
        try:
            # Intento seguro de deserializar los hallazgos estructurados guardados en JSON
            if r.logs:
                parsed_logs = json.loads(r.logs)
        except Exception:
            pass
            
        historical_data.append({
            "id": r.id,
            "target": r.target, 
            "status": r.status, 
            "risk_score": r.risk_score, 
            "findings_count": r.findings_count,
            "detailed_findings_with_remediation_and_legal_framework": parsed_logs,
            "timestamp": str(r.timestamp)
        })

    return JSONResponse({
        "engine": "Container Vuln Engine (Ethical Hacking & Remediation Edition)",
        "current_status": scan_status["status"],
        "current_risk_score": scan_status["risk_score"],
        "historical_audits_count": len(historical_data),
        "historical_records": historical_data
    })

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
EOF
