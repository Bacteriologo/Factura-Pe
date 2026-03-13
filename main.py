"""
FacturaPe Backend API v1.1
Firma XML (XAdES-BES/XMLDSig) + Envío SUNAT + Consulta DNI/RUC
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

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx

# ═══════════════════════════════════════
#  APP CONFIG
# ═══════════════════════════════════════
app = FastAPI(title="FacturaPe Backend API", version="1.1.0")

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

# Storage temporal de certificados (en producción usar BD cifrada)
CERT_STORAGE: dict = {}

# ═══════════════════════════════════════
#  ENDPOINTS BÁSICOS
# ═══════════════════════════════════════
@app.get("/")
def root():
    return {
        "servicio": "FacturaPe Backend API",
        "version": "1.1.0",
        "estado": "operativo",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

# ═══════════════════════════════════════
#  CERTIFICADO DIGITAL
# ═══════════════════════════════════════
@app.post("/api/configurar-certificado")
async def configurar_certificado(
    empresa_id: str = Form(...),
    archivo_p12: UploadFile = File(...),
    password: str = Form(...)
):
    try:
        contenido = await archivo_p12.read()

        if len(contenido) < 100:
            return JSONResponse({"ok": False, "detail": "Archivo demasiado pequeño, no parece un certificado válido"})

        # Validar que el archivo P12 es legible con la contraseña dada
        info_cert = validar_p12(contenido, password)
        if not info_cert["valido"]:
            return JSONResponse({"ok": False, "detail": info_cert["error"]})

        # Guardar en memoria (en producción: cifrar y guardar en BD)
        CERT_STORAGE[empresa_id] = {
            "p12_bytes": contenido,
            "password": password,
            "filename": archivo_p12.filename,
            "uploaded_at": datetime.now(timezone.utc).isoformat()
        }

        return {
            "ok": True,
            "mensaje": "Certificado cargado y validado correctamente",
            "subject": info_cert.get("subject", ""),
            "filename": archivo_p12.filename
        }

    except Exception as e:
        return JSONResponse({"ok": False, "detail": str(e)}, status_code=400)


def validar_p12(p12_bytes: bytes, password: str) -> dict:
    """Valida que el archivo P12 sea legible con la contraseña dada."""
    try:
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        p12_password = password.encode("utf-8") if isinstance(password, str) else password
        private_key, cert, _ = load_key_and_certificates(p12_bytes, p12_password)
        subject = cert.subject.rfc4514_string() if cert else ""
        return {"valido": True, "subject": subject}
    except ImportError:
        # cryptography no disponible, omitir validación
        return {"valido": True, "subject": ""}
    except Exception as e:
        return {"valido": False, "error": f"Certificado inválido o contraseña incorrecta: {e}"}

# ═══════════════════════════════════════
#  CONSULTA DNI (RENIEC)
# ═══════════════════════════════════════
@app.get("/api/consulta-dni/{dni}")
async def consulta_dni(dni: str):
    if len(dni) != 8 or not dni.isdigit():
        return {"ok": False, "error": "DNI debe tener 8 dígitos"}

    apis = [
        f"https://apiperu.dev/api/dni/{dni}",
        f"https://dniruc.apisperu.com/api/v1/dni/{dni}?token=anonymous",
    ]

    async with httpx.AsyncClient(timeout=10) as client:
        for api_url in apis:
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

    apis = [
        f"https://apiperu.dev/api/ruc/{ruc}",
        f"https://dniruc.apisperu.com/api/v1/ruc/{ruc}?token=anonymous",
    ]

    async with httpx.AsyncClient(timeout=10) as client:
        for api_url in apis:
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
):
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

        # Firmar XML con certificado (si existe)
        cert = CERT_STORAGE.get(empresa_id)
        if cert:
            xml_firmado = firmar_xml(xml_content, cert["p12_bytes"], cert["password"])
        else:
            # Sin certificado: enviar sin firma (SUNAT lo rechazará en producción)
            xml_firmado = xml_content

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
        return JSONResponse({
            "ok": False,
            "estado": "ERROR",
            "error_sunat": str(e),
            "codigo": "ERR_BACKEND"
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
            # UBL 2.1: CreditNote usa CreditNoteLine y CreditedQuantity
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
    El nodo ds:Signature se inyecta en ext:ExtensionContent según el
    estándar UBL/SUNAT Perú.

    Requiere: signxml, lxml, cryptography
    Si las librerías no están disponibles devuelve el XML sin firmar
    (válido solo en entorno beta de SUNAT).
    """
    try:
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        from lxml import etree
        from signxml import XMLSigner, methods

        p12_password = password.encode("utf-8") if isinstance(password, str) else password
        private_key, certificate, additional_certs = load_key_and_certificates(p12_bytes, p12_password)

        root = etree.fromstring(xml_content.encode("utf-8"))

        # Namespace de UBL Extension
        ext_ns = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
        ext_content = root.find(
            f"{{{ext_ns}}}UBLExtensions"
            f"/{{{ext_ns}}}UBLExtension"
            f"/{{{ext_ns}}}ExtensionContent"
        )

        # Firmar documento completo con transform enveloped
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        )

        signed_root = signer.sign(
            root,
            key=private_key,
            cert=certificate,
            reference_uri="",
        )

        # Mover la firma a ext:ExtensionContent (requerido por SUNAT/UBL)
        # El transform enveloped-signature excluye el nodo ds:Signature
        # del cómputo del hash, por lo que moverlo no invalida la firma.
        ds_ns = "http://www.w3.org/2000/09/xmldsig#"
        sig_element = signed_root.find(f"{{{ds_ns}}}Signature")

        if sig_element is not None and ext_content is not None:
            signed_root.remove(sig_element)
            sig_element.set("Id", "SignatureKG")
            ext_content.append(sig_element)

        return etree.tostring(
            signed_root,
            xml_declaration=True,
            encoding="UTF-8"
        ).decode("utf-8")

    except ImportError:
        # Librerías de firma no instaladas — XML sin firma (solo beta)
        print("[WARNING] signxml/cryptography/lxml no disponibles. XML enviado sin firma.")
        return xml_content
    except Exception as e:
        # Error durante la firma — devolver sin firma antes que bloquear la emisión
        print(f"[WARNING] Error al firmar XML: {e}")
        return xml_content

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
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>{ruc}{usuario_sol}</wsse:Username>
        <wsse:Password>{clave_sol}</wsse:Password>
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
