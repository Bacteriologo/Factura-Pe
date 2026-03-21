"""
FacturaPe Backend API v1.2
Firma XML (XAdES-BES/XMLDSig) + Envío SUNAT + Consulta DNI/RUC + Certificado cifrado en Supabase
Deploy: Railway
"""
import os
import re
import json
import base64
import hashlib
import zipfile
import io
from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from lxml import etree as lxml_etree
from supabase import create_client, Client

# ═══════════════════════════════════════
#  APP CONFIG
# ═══════════════════════════════════════
app = FastAPI(title="FacturaPe Backend API", version="1.2.0")

# CORS - dominios permitidos
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://bacteriologo.github.io").split(",")
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS if o.strip()]
# Siempre permitir localhost para desarrollo
ALLOWED_ORIGINS += ["http://localhost:8000", "http://localhost:3000", "http://127.0.0.1:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)

# Storage temporal de certificados en memoria
CERT_STORAGE: dict = {}

# ═══════════════════════════════════════
#  SUPABASE CONFIG
# ═══════════════════════════════════════
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://kwmhqkgcyomvqkklvqtp.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt3bWhxa2djeW9tdnFra2x2cXRwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzMyNTQwMjEsImV4cCI6MjA4ODgzMDAyMX0.oWCmTlUgQtDHI7PXhsW53dSwmu9Y1UtPORTW8pt3VJU")

DECOLECTA_KEY = os.getenv("DECOLECTA_KEY", "sk_13958.n3vXxo55kzIUhj1z0tr8nc14ToqNnw1o")

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✓ Supabase conectado correctamente")
except Exception as e:
    print(f"✗ Error conectando Supabase: {e}")
    supabase = None

# ═══════════════════════════════════════════════════════════════
#  FUNCIONES DE CIFRADO AES-256-CBC
# ═══════════════════════════════════════════════════════════════

def generar_clave_desde_password(password: str, salt: bytes) -> bytes:
    """Genera una clave AES-256 a partir de la contraseña usando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def cifrar_certificado(cert_bytes: bytes, password: str, salt: bytes) -> str:
    """
    Cifra el certificado .p12 usando AES-256-CBC.
    Retorna: base64(IV + datos_cifrados)
    """
    clave = generar_clave_desde_password(password, salt)

    # Generar IV aleatorio de 16 bytes
    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(clave),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Padding manual (PKCS7)
    padding_length = 16 - (len(cert_bytes) % 16)
    padded_data = cert_bytes + bytes([padding_length] * padding_length)

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Concatenar IV + datos cifrados y codificar en base64
    combined = iv + encrypted_data
    return base64.b64encode(combined).decode('utf-8')


def descifrar_certificado(cert_cifrado_b64: str, password: str, salt_b64: str) -> bytes:
    """Descifra el certificado desde base64."""
    salt = base64.b64decode(salt_b64)
    clave = generar_clave_desde_password(password, salt)

    combined = base64.b64decode(cert_cifrado_b64)

    # Separar IV (primeros 16 bytes) y datos cifrados
    iv = combined[:16]
    encrypted_data = combined[16:]

    cipher = Cipher(
        algorithms.AES(clave),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remover padding
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

# ═══════════════════════════════════════
#  ENDPOINTS BÁSICOS
# ═══════════════════════════════════════
@app.get("/")
def root():
    return {
        "servicio": "FacturaPe Backend API",
        "version": "1.2.0",
        "estado": "operativo",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health")
def health():
    # Verificar que lxml y cryptography están disponibles (requeridos para firma)
    libs = {}
    try:
        import lxml; libs["lxml"] = lxml.__version__
    except Exception as e:
        libs["lxml"] = f"ERROR: {e}"
    try:
        import cryptography; libs["cryptography"] = cryptography.__version__
    except Exception as e:
        libs["cryptography"] = f"ERROR: {e}"
    return {
        "status": "healthy",
        "firma_disponible": "ERROR" not in libs.get("lxml","") and "ERROR" not in libs.get("cryptography",""),
        "libs": libs
    }

# ═══════════════════════════════════════
#  CERTIFICADO DIGITAL
# ═══════════════════════════════════════
@app.post("/api/configurar-certificado")
async def configurar_certificado(
    empresa_id: str = Form(...),
    archivo_p12: UploadFile = File(...),
    password: str = Form(...)
):
    """
    Carga, valida y guarda cifrado el certificado digital en Supabase.
    """
    try:
        cert_bytes = await archivo_p12.read()

        if len(cert_bytes) < 100:
            return JSONResponse({
                "ok": False,
                "detail": "Archivo demasiado pequeño, no parece un certificado válido"
            })

        # Validar certificado con la contraseña dada
        info_cert = validar_p12(cert_bytes, password)
        if not info_cert["valido"]:
            return JSONResponse({
                "ok": False,
                "code": "INVALID_CERT_PASS",
                "detail": info_cert["error"],
                "mensaje": "Contraseña incorrecta o certificado inválido"
            }, status_code=400)

        dias_restantes = info_cert.get("dias_restantes")

        if dias_restantes is not None and dias_restantes <= 0:
            return JSONResponse({
                "ok": False,
                "code": "CERT_EXPIRED",
                "mensaje": f"Certificado vencido desde hace {abs(dias_restantes)} días"
            }, status_code=400)

        # Guardar en memoria (para uso inmediato)
        CERT_STORAGE[empresa_id] = {
            "p12_bytes": cert_bytes,
            "password": password,
            "filename": archivo_p12.filename,
            "uploaded_at": datetime.now(timezone.utc).isoformat()
        }

        # Cifrar y guardar en Supabase
        if supabase:
            try:
                salt = os.urandom(32)
                salt_b64 = base64.b64encode(salt).decode('utf-8')
                cert_cifrado = cifrar_certificado(cert_bytes, password, salt)

                supabase.table('empresas').update({
                    'certificado_cifrado': cert_cifrado,
                    'certificado_salt': salt_b64
                }).eq('id', empresa_id).execute()

                print(f"✓ Certificado cifrado guardado en BD para empresa {empresa_id}")
            except Exception as e:
                print(f"⚠️ Error guardando certificado en Supabase: {e}")
                # No retornar error — al menos quedó en memoria

        return {
            "ok": True,
            "mensaje": "Certificado configurado y guardado correctamente",
            "subject": info_cert.get("subject", ""),
            "filename": archivo_p12.filename,
            "dias_restantes": dias_restantes
        }

    except Exception as e:
        return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)


def cargar_certificado_desde_bd(empresa_id: str, password: str) -> dict:
    """
    Carga el certificado desde Supabase si no está en memoria.
    Intenta primero con el sistema cifrado (certificado_cifrado/salt),
    luego con el backup en base64 (cert_b64/cert_pass).
    Retorna el dict para CERT_STORAGE o None si no existe/falla.
    """
    if not supabase:
        return None

    try:
        response = supabase.table('empresas').select(
            'certificado_cifrado, certificado_salt, cert_b64, cert_pass'
        ).eq('id', empresa_id).single().execute()

        if not response.data:
            return None

        data = response.data

        # ── Intento 1: sistema cifrado AES (backend) ──────────────────
        cert_cifrado = data.get('certificado_cifrado')
        salt_b64 = data.get('certificado_salt')

        if cert_cifrado and salt_b64:
            try:
                cert_bytes = descifrar_certificado(cert_cifrado, password, salt_b64)
                info = validar_p12(cert_bytes, password)
                if info["valido"]:
                    print(f"✓ Certificado cargado desde BD (cifrado) para empresa {empresa_id}")
                    return {
                        "p12_bytes": cert_bytes,
                        "password": password,
                        "filename": "certificado.p12",
                        "dias_restantes": info.get("dias_restantes"),
                        "uploaded_at": datetime.now(timezone.utc).isoformat()
                    }
            except Exception as e:
                print(f"⚠️ Fallo al descifrar cert AES: {e} — intentando fallback b64")

        # ── Intento 2: backup base64 directo (Supabase) ───────────────
        cert_b64_raw = data.get('cert_b64')
        cert_pass_db = data.get('cert_pass')

        if cert_b64_raw and cert_pass_db:
            try:
                cert_bytes = base64.b64decode(cert_b64_raw)
                info = validar_p12(cert_bytes, cert_pass_db)
                if info["valido"]:
                    print(f"✓ Certificado cargado desde BD (b64) para empresa {empresa_id}")
                    return {
                        "p12_bytes": cert_bytes,
                        "password": cert_pass_db,
                        "filename": "certificado.p12",
                        "dias_restantes": info.get("dias_restantes"),
                        "uploaded_at": datetime.now(timezone.utc).isoformat()
                    }
            except Exception as e:
                print(f"⚠️ Fallo al cargar cert b64: {e}")

        return None

    except Exception as e:
        print(f"✗ Error cargando certificado desde BD: {e}")
        return None


@app.post("/api/eliminar-certificado")
async def eliminar_certificado(
    empresa_id: str = Body(..., embed=True)
):
    """Elimina el certificado digital de memoria y de base de datos."""
    try:
        # Eliminar de memoria
        if empresa_id in CERT_STORAGE:
            del CERT_STORAGE[empresa_id]
            print(f"✓ Certificado eliminado de memoria para empresa {empresa_id}")

        # Eliminar de Supabase
        if supabase:
            try:
                supabase.table('empresas').update({
                    'certificado_cifrado': None,
                    'certificado_salt': None
                }).eq('id', empresa_id).execute()
                print(f"✓ Certificado eliminado de BD para empresa {empresa_id}")
            except Exception as e:
                print(f"⚠️ Error eliminando de BD: {e}")

        return {"ok": True, "mensaje": "Certificado eliminado correctamente"}

    except Exception as e:
        return JSONResponse({
            "ok": False,
            "detail": str(e),
            "mensaje": "Error al eliminar certificado"
        }, status_code=400)


def validar_p12(p12_bytes: bytes, password: str) -> dict:
    """Valida que el archivo P12 sea legible con la contraseña dada.
    Devuelve subject y días restantes de validez si está disponible."""
    try:
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        p12_password = password.encode("utf-8") if isinstance(password, str) else password
        private_key, cert, _ = load_key_and_certificates(p12_bytes, p12_password)
        subject = cert.subject.rfc4514_string() if cert else ""
        dias_restantes = None
        if cert:
            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
            delta = not_after - datetime.now(timezone.utc)
            dias_restantes = max(0, delta.days)
        return {"valido": True, "subject": subject, "dias_restantes": dias_restantes}
    except ImportError:
        return {"valido": True, "subject": "", "dias_restantes": None}
    except Exception as e:
        return {"valido": False, "error": f"Certificado inválido o contraseña incorrecta: {e}"}

# ═══════════════════════════════════════
#  CONSULTA DNI (RENIEC)
# ═══════════════════════════════════════
@app.get("/api/consulta-dni/{dni}")
async def consulta_dni(dni: str):
    if len(dni) != 8 or not dni.isdigit():
        return {"ok": False, "error": "DNI debe tener 8 dígitos"}

    async with httpx.AsyncClient(timeout=10) as client:
        # ── Decolecta (primario) ──────────────────────────────────────
        try:
            resp = await client.get(
                f"https://api.decolecta.com/v1/reniec/dni?numero={dni}",
                headers={"Authorization": f"Bearer {DECOLECTA_KEY}"}
            )
            if resp.status_code == 200:
                data = resp.json()
                nombre = (
                    data.get("full_name") or
                    f"{data.get('first_last_name', '')} {data.get('second_last_name', '')} {data.get('first_name', '')}".strip()
                )
                if nombre and nombre.strip():
                    return {"ok": True, "nombre": nombre.strip(), "dni": dni}
        except Exception:
            pass

        # ── Fallback APIs públicas ────────────────────────────────────
        for api_url in [
            f"https://apiperu.dev/api/dni/{dni}",
            f"https://dniruc.apisperu.com/api/v1/dni/{dni}?token=anonymous",
        ]:
            try:
                resp = await client.get(api_url)
                if resp.status_code == 200:
                    data = resp.json()
                    nombre = (
                        data.get("nombre_completo") or
                        data.get("nombre") or
                        f"{data.get('nombres', '')} {data.get('apellidoPaterno', '')} {data.get('apellidoMaterno', '')}".strip() or
                        f"{data.get('nombres', '')} {data.get('apellido_paterno', '')} {data.get('apellido_materno', '')}".strip()
                    )
                    if nombre and nombre.strip():
                        return {"ok": True, "nombre": nombre.strip(), "dni": dni}
            except Exception:
                continue

    return {"ok": False, "error": "No se pudo consultar el DNI", "dni": dni}

# ═══════════════════════════════════════
#  CONSULTA RUC (SUNAT)
# ═══════════════════════════════════════
@app.get("/api/consulta-ruc/{ruc}")
async def consulta_ruc(ruc: str):
    if len(ruc) != 11 or not ruc.isdigit():
        return {"ok": False, "error": "RUC debe tener 11 dígitos"}

    async with httpx.AsyncClient(timeout=10) as client:
        # ── Decolecta (primario) ──────────────────────────────────────
        try:
            resp = await client.get(
                f"https://api.decolecta.com/v1/sunat/ruc?numero={ruc}",
                headers={"Authorization": f"Bearer {DECOLECTA_KEY}"}
            )
            if resp.status_code == 200:
                data = resp.json()
                razon = (
                    data.get("razonSocial") or
                    data.get("razon_social") or
                    data.get("nombre_o_razon_social") or
                    data.get("nombre") or ""
                )
                direccion = (
                    data.get("direccion") or
                    data.get("direccionCompleta") or
                    data.get("direccion_completa") or ""
                )
                if razon:
                    return {
                        "ok": True,
                        "razon_social": razon,
                        "direccion": direccion,
                        "ruc": ruc,
                        "estado": data.get("estado", ""),
                        "condicion": data.get("condicion", "")
                    }
        except Exception:
            pass

        # ── Fallback APIs públicas ────────────────────────────────────
        for api_url in [
            f"https://apiperu.dev/api/ruc/{ruc}",
            f"https://dniruc.apisperu.com/api/v1/ruc/{ruc}?token=anonymous",
        ]:
            try:
                resp = await client.get(api_url)
                if resp.status_code == 200:
                    data = resp.json()
                    razon = (
                        data.get("razon_social") or
                        data.get("nombre_o_razon_social") or
                        data.get("name") or ""
                    )
                    direccion = (
                        data.get("direccion") or
                        data.get("direccion_completa") or
                        data.get("address") or ""
                    )
                    if razon:
                        return {
                            "ok": True,
                            "razon_social": razon,
                            "direccion": direccion,
                            "ruc": ruc,
                            "estado": data.get("estado", ""),
                            "condicion": data.get("condicion", "")
                        }
            except Exception:
                continue

    return {"ok": False, "error": "No se pudo consultar el RUC", "ruc": ruc}

# ═══════════════════════════════════════
#  EMISIÓN DE COMPROBANTES
# ═══════════════════════════════════════
@app.post("/api/emitir")
async def emitir_comprobante(
    empresa_id: str = Form(...),
    ruc_emisor: str = Form(...),
    usuario_sol: str = Form(...),
    clave_sol: str = Form(...),
    ambiente: str = Form("beta"),
    tipo: str = Form(...),
    serie: str = Form(...),
    numero: str = Form(...),
    nombre_emisor: str = Form(""),
    direccion_emisor: str = Form(""),
    ubigeo_emisor: str = Form("150101"),
    cliente_nombre: str = Form("Cliente Final"),
    cliente_tipo_doc: str = Form("1"),
    cliente_num_doc: str = Form("-"),
    items_json: str = Form("[]"),
    total: str = Form("0"),
    # Campos opcionales para Nota de Crédito
    motivo_nc: str = Form(""),
    descripcion_nc: str = Form(""),
    ref_tipo: str = Form(""),
    ref_numero: str = Form(""),
    # Contraseña del certificado (opcional, para carga automática desde BD)
    cert_password: str = Form(""),
):
    # ── Intentar cargar certificado desde memoria o BD ────────────────
    if empresa_id not in CERT_STORAGE:
        if cert_password:
            cert_data = cargar_certificado_desde_bd(empresa_id, cert_password)
            if cert_data:
                CERT_STORAGE[empresa_id] = cert_data
                print(f"✓ Certificado cargado desde BD para empresa {empresa_id}")

    # ── Verificar certificado digital ────────────────────────────────
    cert = CERT_STORAGE.get(empresa_id)
    if not cert or not cert.get("p12_bytes"):
        return JSONResponse({
            "ok": False,
            "estado": "ERROR",
            "codigo": "NO_CERT",
            "error_sunat": "No hay certificado digital cargado",
            "mensaje": "Debes cargar tu certificado digital (.p12/.pfx) en Configuración antes de poder emitir comprobantes."
        }, status_code=400)
    if not cert.get("password"):
        return JSONResponse({
            "ok": False,
            "estado": "ERROR",
            "codigo": "NO_CERT_PASS",
            "error_sunat": "Falta contraseña del certificado",
            "mensaje": "El certificado fue cargado pero falta la contraseña. Vuelve a cargarlo en Configuración."
        }, status_code=400)

    # ── Validaciones de entrada ──────────────────────────────────────
    if len(ruc_emisor) != 11 or not ruc_emisor.isdigit():
        return JSONResponse({"ok": False, "error_sunat": "RUC emisor inválido (debe tener 11 dígitos)"}, status_code=400)

    TIPOS_VALIDOS = {"BOLETA", "FACTURA", "NOTA_CREDITO"}
    if tipo not in TIPOS_VALIDOS:
        return JSONResponse({"ok": False, "error_sunat": f"Tipo de comprobante inválido. Use: {TIPOS_VALIDOS}"}, status_code=400)

    if ambiente not in {"beta", "prod"}:
        return JSONResponse({"ok": False, "error_sunat": "Ambiente inválido. Use 'beta' o 'prod'"}, status_code=400)

    if not numero.isdigit():
        return JSONResponse({"ok": False, "error_sunat": "El número de comprobante debe ser numérico"}, status_code=400)

    try:
        total_num = float(total)
        if total_num <= 0:
            raise ValueError
    except ValueError:
        return JSONResponse({"ok": False, "error_sunat": "Total inválido"}, status_code=400)

    try:
        items = json.loads(items_json)
        if not isinstance(items, list) or len(items) == 0:
            raise ValueError
    except (json.JSONDecodeError, ValueError):
        return JSONResponse({"ok": False, "error_sunat": "Items inválidos o vacíos"}, status_code=400)

    # Validar items individuales
    for i, item in enumerate(items):
        if not isinstance(item.get("name"), str) or not item["name"].strip():
            return JSONResponse({"ok": False, "error_sunat": f"Item {i+1}: nombre requerido"}, status_code=400)
        try:
            qty = float(item.get("qty", 0))
            price = float(item.get("price", 0))
            if qty <= 0 or price < 0:
                raise ValueError
        except (TypeError, ValueError):
            return JSONResponse({"ok": False, "error_sunat": f"Item {i+1}: cantidad o precio inválido"}, status_code=400)

    # Validar Nota de Crédito tiene referencia
    if tipo == "NOTA_CREDITO" and not ref_numero.strip():
        return JSONResponse({"ok": False, "error_sunat": "Nota de Crédito requiere número de documento de referencia"}, status_code=400)

    try:
        numero_int = int(numero)
        numero_str = str(numero_int).zfill(8)

        # Determinar tipo de documento UBL
        tipo_doc_map = {
            "BOLETA": "03",
            "FACTURA": "01",
            "NOTA_CREDITO": "07",
        }
        tipo_doc = tipo_doc_map[tipo]

        # En beta/homologación SUNAT exige formato estricto de serie:
        # Boleta → B***, Factura → F***
        # En producción se acepta la serie registrada (ej: E001 si la empresa ya la tiene)
        if ambiente == "beta":
            if tipo == "BOLETA" and not serie.upper().startswith("B"):
                return JSONResponse({
                    "ok": False,
                    "estado": "ERROR",
                    "codigo": "1773_BETA",
                    "error_sunat": (
                        f"En el entorno BETA, la serie de BOLETA debe empezar con 'B' (ej: B001). "
                        f"Serie actual: '{serie}'. "
                        "Cambia la Serie Boleta en Configuración solo para las pruebas. "
                        "En producción puedes usar tu serie real."
                    )
                }, status_code=400)

            if tipo == "FACTURA" and not serie.upper().startswith("F"):
                return JSONResponse({
                    "ok": False,
                    "estado": "ERROR",
                    "codigo": "1773_BETA",
                    "error_sunat": (
                        f"En el entorno BETA, la serie de FACTURA debe empezar con 'F' (ej: F001). "
                        f"Serie actual: '{serie}'. "
                        "Cambia la Serie Factura en Configuración solo para las pruebas. "
                        "En producción puedes usar tu serie real (ej: E001)."
                    )
                }, status_code=400)

        # Calcular montos
        base_imponible = round(total_num / 1.18, 2)
        igv = round(total_num - base_imponible, 2)

        # Generar XML UBL 2.1
        xml_content = generar_xml_ubl(
            ruc=ruc_emisor,
            tipo_doc=tipo_doc,
            serie=serie,
            numero=numero_str,
            nombre_emisor=nombre_emisor,
            direccion_emisor=direccion_emisor,
            ubigeo=ubigeo_emisor,
            cliente_nombre=cliente_nombre,
            cliente_tipo_doc=cliente_tipo_doc,
            cliente_num_doc=cliente_num_doc,
            items=items,
            base_imponible=base_imponible,
            igv=igv,
            total=total_num,
            motivo_nc=motivo_nc,
            ref_tipo=ref_tipo,
            ref_numero=ref_numero,
            descripcion_nc=descripcion_nc,
        )

        # Firmar XML con certificado (cert ya fue validado arriba)
        xml_firmado = firmar_xml(xml_content, cert["p12_bytes"], cert["password"])

        # Crear ZIP
        zip_filename = f"{ruc_emisor}-{tipo_doc}-{serie}-{numero_str}"
        zip_buffer = crear_zip(zip_filename, xml_firmado)

        # Enviar a SUNAT
        if ambiente == "prod":
            url_sunat = "https://e-factura.sunat.gob.pe/ol-ti-itcpfegem/billService"
        else:
            url_sunat = "https://e-beta.sunat.gob.pe/ol-ti-itcpfegem-beta/billService"

        resultado = await enviar_sunat(
            url=url_sunat,
            ruc=ruc_emisor,
            usuario_sol=usuario_sol,
            clave_sol=clave_sol,
            zip_filename=zip_filename + ".zip",
            zip_content=zip_buffer,
        )

        return resultado

    except Exception as e:
        error_msg = str(e)
        # Código específico para errores de firma para mejor UX en frontend
        codigo = "FIRMA_ERR" if "firmar" in error_msg.lower() or "firma" in error_msg.lower() or "sign" in error_msg.lower() or "librería" in error_msg.lower() else "ERR_BACKEND"
        return JSONResponse({
            "ok": False,
            "estado": "ERROR",
            "error_sunat": error_msg,
            "codigo": codigo
        }, status_code=500)

# ═══════════════════════════════════════
#  GENERACIÓN XML UBL 2.1
# ═══════════════════════════════════════
def generar_xml_ubl(ruc, tipo_doc, serie, numero, nombre_emisor, direccion_emisor,
                     ubigeo, cliente_nombre, cliente_tipo_doc, cliente_num_doc,
                     items, base_imponible, igv, total, motivo_nc="",
                     ref_tipo="", ref_numero="", descripcion_nc=""):

    fecha = datetime.now().strftime("%Y-%m-%d")
    hora = datetime.now().strftime("%H:%M:%S")
    is_credit_note = tipo_doc == "07"

    # Líneas de items
    items_xml = ""
    for idx, item in enumerate(items, 1):
        qty = item.get("qty", 1)
        price = float(item.get("price", 0))
        name = item.get("name", "Producto")
        unit = item.get("unit", "NIU")
        line_total = round(qty * price, 2)
        line_base = round(line_total / 1.18, 2)
        line_igv = round(line_total - line_base, 2)
        price_sin_igv = round(price / 1.18, 5)

        if is_credit_note:
            items_xml += f"""
    <cac:CreditNoteLine>
      <cbc:ID>{idx}</cbc:ID>
      <cbc:CreditedQuantity unitCode="{unit}">{qty}</cbc:CreditedQuantity>
      <cbc:LineExtensionAmount currencyID="PEN">{line_base}</cbc:LineExtensionAmount>
      <cac:PricingReference>
        <cac:AlternativeConditionPrice>
          <cbc:PriceAmount currencyID="PEN">{price}</cbc:PriceAmount>
          <cbc:PriceTypeCode>01</cbc:PriceTypeCode>
        </cac:AlternativeConditionPrice>
      </cac:PricingReference>
      <cac:TaxTotal>
        <cbc:TaxAmount currencyID="PEN">{line_igv}</cbc:TaxAmount>
        <cac:TaxSubtotal>
          <cbc:TaxableAmount currencyID="PEN">{line_base}</cbc:TaxableAmount>
          <cbc:TaxAmount currencyID="PEN">{line_igv}</cbc:TaxAmount>
          <cac:TaxCategory>
            <cbc:Percent>18</cbc:Percent>
            <cbc:TaxExemptionReasonCode>10</cbc:TaxExemptionReasonCode>
            <cac:TaxScheme>
              <cbc:ID>1000</cbc:ID>
              <cbc:Name>IGV</cbc:Name>
              <cbc:TaxTypeCode>VAT</cbc:TaxTypeCode>
            </cac:TaxScheme>
          </cac:TaxCategory>
        </cac:TaxSubtotal>
      </cac:TaxTotal>
      <cac:Item>
        <cbc:Description><![CDATA[{name}]]></cbc:Description>
      </cac:Item>
      <cac:Price>
        <cbc:PriceAmount currencyID="PEN">{price_sin_igv}</cbc:PriceAmount>
      </cac:Price>
    </cac:CreditNoteLine>"""
        else:
            items_xml += f"""
    <cac:InvoiceLine>
      <cbc:ID>{idx}</cbc:ID>
      <cbc:InvoicedQuantity unitCode="{unit}">{qty}</cbc:InvoicedQuantity>
      <cbc:LineExtensionAmount currencyID="PEN">{line_base}</cbc:LineExtensionAmount>
      <cac:PricingReference>
        <cac:AlternativeConditionPrice>
          <cbc:PriceAmount currencyID="PEN">{price}</cbc:PriceAmount>
          <cbc:PriceTypeCode>01</cbc:PriceTypeCode>
        </cac:AlternativeConditionPrice>
      </cac:PricingReference>
      <cac:TaxTotal>
        <cbc:TaxAmount currencyID="PEN">{line_igv}</cbc:TaxAmount>
        <cac:TaxSubtotal>
          <cbc:TaxableAmount currencyID="PEN">{line_base}</cbc:TaxableAmount>
          <cbc:TaxAmount currencyID="PEN">{line_igv}</cbc:TaxAmount>
          <cac:TaxCategory>
            <cbc:Percent>18</cbc:Percent>
            <cbc:TaxExemptionReasonCode>10</cbc:TaxExemptionReasonCode>
            <cac:TaxScheme>
              <cbc:ID>1000</cbc:ID>
              <cbc:Name>IGV</cbc:Name>
              <cbc:TaxTypeCode>VAT</cbc:TaxTypeCode>
            </cac:TaxScheme>
          </cac:TaxCategory>
        </cac:TaxSubtotal>
      </cac:TaxTotal>
      <cac:Item>
        <cbc:Description><![CDATA[{name}]]></cbc:Description>
      </cac:Item>
      <cac:Price>
        <cbc:PriceAmount currencyID="PEN">{price_sin_igv}</cbc:PriceAmount>
      </cac:Price>
    </cac:InvoiceLine>"""

    # Referencia para Nota de Crédito
    ref_xml = ""
    if is_credit_note and ref_numero:
        ref_tipo_code = ref_tipo or "03"
        ref_xml = f"""
    <cac:BillingReference>
      <cac:InvoiceDocumentReference>
        <cbc:ID>{ref_numero}</cbc:ID>
        <cbc:DocumentTypeCode>{ref_tipo_code}</cbc:DocumentTypeCode>
      </cac:InvoiceDocumentReference>
    </cac:BillingReference>
    <cac:DiscrepancyResponse>
      <cbc:ReferenceID>{ref_numero}</cbc:ReferenceID>
      <cbc:ResponseCode>{motivo_nc or '01'}</cbc:ResponseCode>
      <cbc:Description><![CDATA[{descripcion_nc or 'Anulacion de la operacion'}]]></cbc:Description>
    </cac:DiscrepancyResponse>"""

    root_tag = "CreditNote" if is_credit_note else "Invoice"

    # InvoiceTypeCode solo aplica a Invoice (Factura/Boleta), no a CreditNote
    type_code_xml = ""
    if not is_credit_note:
        type_code_xml = f"\n  <cbc:InvoiceTypeCode listID=\"0101\">{tipo_doc}</cbc:InvoiceTypeCode>"

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<{root_tag} xmlns="urn:oasis:names:specification:ubl:schema:xsd:{root_tag}-2"
  xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
  xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
  xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent/>
    </ext:UBLExtension>
  </ext:UBLExtensions>
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>2.0</cbc:CustomizationID>
  <cbc:ID>{serie}-{numero}</cbc:ID>
  <cbc:IssueDate>{fecha}</cbc:IssueDate>
  <cbc:IssueTime>{hora}</cbc:IssueTime>{type_code_xml}
  <cbc:DocumentCurrencyCode>PEN</cbc:DocumentCurrencyCode>{ref_xml}
  <cac:Signature>
    <cbc:ID>IDSignKG</cbc:ID>
    <cac:SignatoryParty>
      <cac:PartyIdentification><cbc:ID>{ruc}</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name><![CDATA[{nombre_emisor}]]></cbc:Name></cac:PartyName>
    </cac:SignatoryParty>
    <cac:DigitalSignatureAttachment>
      <cac:ExternalReference><cbc:URI>#SignatureKG</cbc:URI></cac:ExternalReference>
    </cac:DigitalSignatureAttachment>
  </cac:Signature>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="6">{ruc}</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name><![CDATA[{nombre_emisor}]]></cbc:Name></cac:PartyName>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName><![CDATA[{nombre_emisor}]]></cbc:RegistrationName>
        <cac:RegistrationAddress>
          <cbc:ID>{ubigeo}</cbc:ID>
          <cbc:AddressTypeCode>0000</cbc:AddressTypeCode>
          <cac:AddressLine><cbc:Line><![CDATA[{direccion_emisor}]]></cbc:Line></cac:AddressLine>
        </cac:RegistrationAddress>
      </cac:PartyLegalEntity>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="{cliente_tipo_doc}">{cliente_num_doc}</cbc:ID></cac:PartyIdentification>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName><![CDATA[{cliente_nombre}]]></cbc:RegistrationName>
      </cac:PartyLegalEntity>
    </cac:Party>
  </cac:AccountingCustomerParty>
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="PEN">{igv}</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="PEN">{base_imponible}</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="PEN">{igv}</cbc:TaxAmount>
      <cac:TaxCategory>
        <cac:TaxScheme>
          <cbc:ID>1000</cbc:ID>
          <cbc:Name>IGV</cbc:Name>
          <cbc:TaxTypeCode>VAT</cbc:TaxTypeCode>
        </cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="PEN">{base_imponible}</cbc:LineExtensionAmount>
    <cbc:TaxInclusiveAmount currencyID="PEN">{total}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="PEN">{total}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>{items_xml}
</{root_tag}>"""

    return xml

# ═══════════════════════════════════════
#  FIRMA XML (XMLDSig enveloped para SUNAT)
# ═══════════════════════════════════════
def firmar_xml(xml_content: str, p12_bytes: bytes, password: str) -> str:
    """
    Firma el XML con XMLDSig (enveloped) usando el certificado P12.
    Implementado con solo lxml + cryptography (sin signxml).
    El nodo ds:Signature se inyecta en ext:ExtensionContent según el
    estándar UBL/SUNAT Perú.

    Algoritmos:
      - Digest reference:    SHA-256
      - Firma:               RSA-SHA-256 (PKCS1v15)
      - Canonicalización:    C14N 1.0 (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)
    """
    DS      = "http://www.w3.org/2000/09/xmldsig#"
    EXT_NS  = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
    C14N    = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    RSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    DSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    ENVEL   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

    try:
        p12_pwd = password.encode("utf-8") if isinstance(password, str) else password
        private_key, certificate, _ = load_key_and_certificates(p12_bytes, p12_pwd)

        root = lxml_etree.fromstring(xml_content.encode("utf-8"))

        # Localizar ExtensionContent donde SUNAT exige la firma
        ext_content = root.find(
            f"{{{EXT_NS}}}UBLExtensions"
            f"/{{{EXT_NS}}}UBLExtension"
            f"/{{{EXT_NS}}}ExtensionContent"
        )
        if ext_content is None:
            raise RuntimeError("No se encontró ExtensionContent en el XML")

        # ── 1. C14N documento SIN firma → DigestValue de la Reference ──────────
        import hashlib as _hashlib
        buf = io.BytesIO()
        root.getroottree().write_c14n(buf, exclusive=False, with_comments=False)
        doc_c14n = buf.getvalue()
        digest_b64 = base64.b64encode(_hashlib.sha256(doc_c14n).digest()).decode()

        # ── 2. Certificado en base64 (DER) ─────────────────────────────────────
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        cert_b64_str = base64.b64encode(cert_der).decode()

        # ── 3. Construir estructura ds:Signature completa (SignatureValue vacío) ─
        sig_el = lxml_etree.Element(f"{{{DS}}}Signature", nsmap={"ds": DS})
        sig_el.set("Id", "SignatureKG")

        signed_info = lxml_etree.SubElement(sig_el, f"{{{DS}}}SignedInfo")

        c14n_m = lxml_etree.SubElement(signed_info, f"{{{DS}}}CanonicalizationMethod")
        c14n_m.set("Algorithm", C14N)

        sig_m = lxml_etree.SubElement(signed_info, f"{{{DS}}}SignatureMethod")
        sig_m.set("Algorithm", RSHA256)

        ref = lxml_etree.SubElement(signed_info, f"{{{DS}}}Reference")
        ref.set("URI", "")

        transforms = lxml_etree.SubElement(ref, f"{{{DS}}}Transforms")
        t = lxml_etree.SubElement(transforms, f"{{{DS}}}Transform")
        t.set("Algorithm", ENVEL)
        t2 = lxml_etree.SubElement(transforms, f"{{{DS}}}Transform")
        t2.set("Algorithm", C14N)

        dm = lxml_etree.SubElement(ref, f"{{{DS}}}DigestMethod")
        dm.set("Algorithm", DSHA256)

        dv = lxml_etree.SubElement(ref, f"{{{DS}}}DigestValue")
        dv.text = digest_b64

        sv = lxml_etree.SubElement(sig_el, f"{{{DS}}}SignatureValue")

        ki = lxml_etree.SubElement(sig_el, f"{{{DS}}}KeyInfo")
        x5d = lxml_etree.SubElement(ki, f"{{{DS}}}X509Data")
        x5c = lxml_etree.SubElement(x5d, f"{{{DS}}}X509Certificate")
        x5c.text = cert_b64_str

        # ── 4. Insertar firma en documento ANTES de calcular la firma ────────────
        # (necesario para que C14N de SignedInfo incluya namespaces del documento)
        ext_content.append(sig_el)

        # ── 5. C14N de SignedInfo EN CONTEXTO del documento → firmar ────────────
        si_c14n = lxml_etree.tostring(signed_info, method="c14n", exclusive=False, with_comments=False)
        sig_bytes = private_key.sign(si_c14n, asym_padding.PKCS1v15(), hashes.SHA256())
        sv.text = base64.b64encode(sig_bytes).decode()

        return lxml_etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8"
        ).decode("utf-8")

    except Exception as e:
        raise RuntimeError(f"Error al firmar el XML: {e}")

# ═══════════════════════════════════════
#  CREAR ZIP
# ═══════════════════════════════════════
def crear_zip(filename: str, xml_content: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{filename}.xml", xml_content.encode("utf-8"))
    buffer.seek(0)
    return buffer.read()

# ═══════════════════════════════════════
#  ENVIAR A SUNAT (SOAP)
# ═══════════════════════════════════════
async def enviar_sunat(url: str, ruc: str, usuario_sol: str, clave_sol: str,
                       zip_filename: str, zip_content: bytes) -> dict:
    zip_b64 = base64.b64encode(zip_content).decode("utf-8")

    soap_xml = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:ser="http://service.sunat.gob.pe" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:Security soapenv:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>{ruc}{usuario_sol}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{clave_sol}</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body>
    <ser:sendBill>
      <fileName>{zip_filename}</fileName>
      <contentFile>{zip_b64}</contentFile>
    </ser:sendBill>
  </soapenv:Body>
</soapenv:Envelope>"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                url,
                content=soap_xml.encode("utf-8"),
                headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": ""}
            )

        body = response.text

        # Parsear respuesta SUNAT
        if "<applicationResponse>" in body or "<applicationresponse>" in body.lower():
            match = re.search(r"<applicationResponse>(.*?)</applicationResponse>", body, re.DOTALL | re.IGNORECASE)
            if match:
                cdr_b64 = match.group(1).strip()
                cdr_bytes = base64.b64decode(cdr_b64)
                cdr_hash = hashlib.md5(cdr_bytes).hexdigest()[:16]
                cdr_info = parsear_cdr(cdr_bytes)

                if cdr_info.get("codigo") == "0":
                    return {
                        "ok": True,
                        "estado": "ACEPTADO",
                        "cdr_hash": cdr_hash,
                        "mensaje": cdr_info.get("descripcion", "Aceptado"),
                        "observaciones": cdr_info.get("observaciones", [])
                    }
                else:
                    return {
                        "ok": False,
                        "estado": "RECHAZADO",
                        "codigo": cdr_info.get("codigo", "???"),
                        "error_sunat": cdr_info.get("descripcion", "Rechazado por SUNAT"),
                    }

        # Si hay faultstring (error SOAP)
        if "<faultstring>" in body:
            fault = re.search(r"<faultstring>(.*?)</faultstring>", body, re.DOTALL)
            error_msg = fault.group(1).strip() if fault else "Error SOAP desconocido"
            code_match = re.search(r"(\d{4})", error_msg)
            code = code_match.group(1) if code_match else "SOAP_ERR"

            # Mensaje especial para errores de firma digital
            if "signature" in error_msg.lower() or "firmado" in error_msg.lower():
                return {
                    "ok": False,
                    "estado": "RECHAZADO",
                    "codigo": code,
                    "error_sunat": "Problema con la firma digital del comprobante",
                    "mensaje": "El certificado puede estar vencido, corrupto o la contraseña es incorrecta. Verifica en Configuración que hayas cargado un certificado válido."
                }

            return {
                "ok": False,
                "estado": "RECHAZADO",
                "codigo": code,
                "error_sunat": error_msg
            }

        return {
            "ok": False,
            "estado": "ERROR",
            "codigo": f"HTTP_{response.status_code}",
            "error_sunat": f"Respuesta inesperada de SUNAT (HTTP {response.status_code})"
        }

    except httpx.TimeoutException:
        return {"ok": False, "estado": "ERROR", "codigo": "TIMEOUT", "error_sunat": "SUNAT no respondió (timeout 30s)"}
    except Exception as e:
        return {"ok": False, "estado": "ERROR", "codigo": "CONN_ERR", "error_sunat": str(e)}


def parsear_cdr(cdr_bytes: bytes) -> dict:
    """Parsear el ZIP CDR de SUNAT para extraer código y descripción."""
    try:
        cdr_buffer = io.BytesIO(cdr_bytes)
        with zipfile.ZipFile(cdr_buffer) as zf:
            for name in zf.namelist():
                if name.endswith(".xml"):
                    xml_cdr = zf.read(name).decode("utf-8")
                    code = re.search(r"<cbc:ResponseCode>(.*?)</cbc:ResponseCode>", xml_cdr)
                    desc = re.search(r"<cbc:Description>(.*?)</cbc:Description>", xml_cdr)
                    obs = re.findall(r"<cbc:Note>(.*?)</cbc:Note>", xml_cdr)
                    return {
                        "codigo": code.group(1).strip() if code else "???",
                        "descripcion": desc.group(1).strip() if desc else "Sin descripción",
                        "observaciones": obs
                    }
    except Exception:
        pass

    return {"codigo": "???", "descripcion": "No se pudo leer CDR", "observaciones": []}

# ═══════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
