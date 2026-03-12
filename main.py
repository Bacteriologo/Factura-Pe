"""
FacturaPe Backend API
FastAPI server para firma digital y envío a SUNAT
"""
from fastapi import FastAPI, UploadFile, Form, HTTPException, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import json
import os
from typing import Optional

from sunat_xml import generar_xml_comprobante, calcular_hash_cpe
from firma_digital import firmar_xml, cargar_certificado_p12, validar_certificado, extraer_ruc_de_certificado
from sunat_client import SunatClient, CODIGOS_ERROR_SUNAT

# Inicializar FastAPI
app = FastAPI(
    title="FacturaPe Backend",
    description="API para firma digital y emisión de comprobantes electrónicos SUNAT",
    version="1.0.0"
)

# CORS - Permitir requests desde GitHub Pages
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://*.github.io",  # Cualquier GitHub Pages
        "http://localhost:8000",
        "http://localhost:3000",
        "http://127.0.0.1:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Almacenamiento temporal de certificados
# NOTA: En producción usar Redis o base de datos encriptada
CERTIFICADOS_CACHE = {}


@app.get("/")
async def root():
    """Endpoint raíz - verificación de salud"""
    return {
        "servicio": "FacturaPe Backend API",
        "version": "1.0.0",
        "estado": "operativo",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check para Railway/Vercel"""
    return {"status": "healthy"}


@app.post("/api/configurar-certificado")
async def configurar_certificado(
    empresa_id: str = Form(...),
    archivo_p12: UploadFile = File(...),
    password: str = Form(...)
):
    """
    Carga y valida el certificado digital del usuario
    
    Este endpoint se llama UNA VEZ desde el panel Config de la app
    El certificado se guarda en memoria (o BD en producción)
    """
    try:
        # Leer archivo .p12
        contenido = await archivo_p12.read()
        
        # Cargar y validar certificado
        cert_data = cargar_certificado_p12(contenido, password)
        
        # Validar certificado
        validacion = validar_certificado(cert_data)
        
        if not validacion['valido']:
            raise HTTPException(status_code=400, detail=f"Certificado inválido: {validacion.get('error')}")
        
        if validacion.get('vencido'):
            raise HTTPException(status_code=400, detail="El certificado está vencido")
        
        # Extraer RUC del certificado
        ruc_cert = extraer_ruc_de_certificado(cert_data)
        
        # Guardar en cache (en producción: encriptar y guardar en Supabase)
        CERTIFICADOS_CACHE[empresa_id] = {
            'cert_data': cert_data,
            'ruc': ruc_cert,
            'validacion': validacion,
            'fecha_carga': datetime.now().isoformat()
        }
        
        return {
            "ok": True,
            "mensaje": "Certificado configurado correctamente",
            "ruc_certificado": ruc_cert,
            "fecha_vencimiento": validacion.get('fecha_fin'),
            "dias_restantes": validacion.get('dias_restantes', 0)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar certificado: {str(e)}")


@app.post("/api/emitir")
async def emitir_comprobante(
    # Datos de autenticación
    empresa_id: str = Form(...),
    ruc_emisor: str = Form(...),
    usuario_sol: str = Form(...),
    clave_sol: str = Form(...),
    ambiente: str = Form(default='beta'),  # 'beta' o 'produccion'
    
    # Datos del comprobante
    tipo: str = Form(...),  # 'FACTURA' o 'BOLETA'
    serie: str = Form(...),
    numero: int = Form(...),
    
    # Datos del emisor
    nombre_emisor: str = Form(...),
    direccion_emisor: str = Form(default=''),
    ubigeo_emisor: str = Form(default='150101'),
    
    # Datos del cliente
    cliente_nombre: str = Form(default='Cliente Final'),
    cliente_tipo_doc: str = Form(default='1'),  # 1=DNI, 6=RUC
    cliente_num_doc: str = Form(default='-'),
    
    # Items (JSON string)
    items_json: str = Form(...),
    
    # Totales
    total: float = Form(...),
):
    """
    Emite un comprobante electrónico a SUNAT
    
    Flujo:
    1. Genera XML UBL 2.1
    2. Firma con certificado digital
    3. Envía a SUNAT vía SOAP
    4. Procesa CDR
    5. Retorna resultado
    """
    try:
        # 1. Verificar que existe certificado
        if empresa_id not in CERTIFICADOS_CACHE:
            raise HTTPException(
                status_code=400,
                detail="Certificado no configurado. Sube tu certificado .p12 primero en Config."
            )
        
        cert_info = CERTIFICADOS_CACHE[empresa_id]
        cert_data = cert_info['cert_data']
        
        # 2. Parsear items
        try:
            items = json.loads(items_json)
        except:
            raise HTTPException(status_code=400, detail="Items JSON inválido")
        
        # 3. Calcular totales
        base_imponible = total / 1.18
        igv = total - base_imponible
        
        # 4. Preparar items para XML
        items_xml = []
        for item in items:
            cantidad = item.get('qty', item.get('cantidad', 1))
            precio_con_igv = float(item.get('price', item.get('precio', 0)))
            precio_sin_igv = precio_con_igv / 1.18
            valor_total = precio_sin_igv * cantidad
            igv_item = valor_total * 0.18
            
            items_xml.append({
                'codigo': item.get('code', item.get('id', 'PROD')),
                'descripcion': item.get('name', item.get('nombre', 'Producto')),
                'cantidad': cantidad,
                'unidad': item.get('unit', item.get('unidad', 'NIU')),
                'precio_unitario': round(precio_sin_igv, 2),
                'precio_venta': round(precio_con_igv, 2),
                'valor_total': round(valor_total, 2),
                'igv': round(igv_item, 2),
                'total': round(valor_total + igv_item, 2)
            })
        
        # 5. Generar datos del XML
        fecha_actual = datetime.now()
        
        datos_xml = {
            'tipo': tipo,
            'serie': serie,
            'numero': numero,
            'fecha_emision': fecha_actual.strftime('%Y-%m-%d'),
            'hora_emision': fecha_actual.strftime('%H:%M:%S'),
            'moneda': 'PEN',
            
            'emisor': {
                'ruc': ruc_emisor,
                'nombre': nombre_emisor,
                'nombre_comercial': nombre_emisor,
                'ubigeo': ubigeo_emisor,
                'direccion': direccion_emisor or 'Lima, Perú',
                'distrito': 'Lima',
                'provincia': 'Lima',
                'departamento': 'Lima',
                'pais': 'PE'
            },
            
            'cliente': {
                'tipo_doc': cliente_tipo_doc,
                'num_doc': cliente_num_doc,
                'nombre': cliente_nombre
            },
            
            'items': items_xml,
            
            'totales': {
                'gravadas': round(base_imponible, 2),
                'igv': round(igv, 2),
                'total': round(total, 2)
            }
        }
        
        # 6. Generar XML
        xml_sin_firmar = generar_xml_comprobante(datos_xml)
        
        # 7. Firmar XML
        xml_firmado = firmar_xml(xml_sin_firmar, cert_data)
        
        # 8. Enviar a SUNAT
        nombre_archivo = f"{ruc_emisor}-{('01' if tipo=='FACTURA' else '03')}-{serie}-{str(numero).zfill(8)}"
        
        sunat = SunatClient(
            ruc_emisor=ruc_emisor,
            usuario_sol=usuario_sol,
            clave_sol=clave_sol,
            ambiente=ambiente
        )
        
        resultado = sunat.enviar_comprobante(xml_firmado, nombre_archivo)
        
        # 9. Retornar resultado
        if resultado['success']:
            return {
                "ok": True,
                "estado": resultado['estado'],
                "codigo": resultado['codigo'],
                "mensaje": resultado['mensaje'],
                "numero_comprobante": f"{serie}-{str(numero).zfill(8)}",
                "cdr_hash": resultado.get('hash_cdr', ''),
                "observaciones": resultado.get('observaciones', []),
                "xml_firmado": xml_firmado,
                "cdr_base64": resultado.get('cdr_base64', ''),
                "fecha_emision": fecha_actual.isoformat()
            }
        else:
            # Error de SUNAT
            return {
                "ok": False,
                "estado": "RECHAZADO",
                "codigo": resultado['codigo'],
                "mensaje": resultado['mensaje'],
                "error_sunat": CODIGOS_ERROR_SUNAT.get(resultado['codigo'], resultado['mensaje'])
            }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al emitir: {str(e)}")


@app.post("/api/validar-ruc")
async def validar_ruc(ruc: str = Form(...)):
    """
    Valida un RUC en SUNAT (simulado - en producción usar API oficial)
    """
    # TODO: Integrar con API real de SUNAT para validación
    # Por ahora retornamos datos simulados
    
    if len(ruc) != 11 or not ruc.isdigit():
        return {"ok": False, "mensaje": "RUC inválido"}
    
    return {
        "ok": True,
        "ruc": ruc,
        "razon_social": f"EMPRESA EJEMPLO {ruc} SAC",
        "estado": "ACTIVO",
        "condicion": "HABIDO",
        "direccion": "Av. Lima 123, Lima"
    }


@app.post("/api/validar-dni")
async def validar_dni(dni: str = Form(...)):
    """
    Valida un DNI en RENIEC (simulado - en producción requiere convenio)
    """
    # TODO: Integrar con API real de RENIEC
    # Por ahora retornamos datos simulados
    
    if len(dni) != 8 or not dni.isdigit():
        return {"ok": False, "mensaje": "DNI inválido"}
    
    return {
        "ok": True,
        "dni": dni,
        "nombres": "JUAN CARLOS",
        "apellido_paterno": "PÉREZ",
        "apellido_materno": "GARCÍA",
        "nombre_completo": "PÉREZ GARCÍA JUAN CARLOS"
    }


@app.get("/api/estado-certificado/{empresa_id}")
async def estado_certificado(empresa_id: str):
    """
    Consulta el estado del certificado digital cargado
    """
    if empresa_id not in CERTIFICADOS_CACHE:
        return {
            "configurado": False,
            "mensaje": "No hay certificado configurado"
        }
    
    cert_info = CERTIFICADOS_CACHE[empresa_id]
    validacion = cert_info['validacion']
    
    return {
        "configurado": True,
        "ruc": cert_info['ruc'],
        "fecha_vencimiento": validacion.get('fecha_fin'),
        "dias_restantes": validacion.get('dias_restantes', 0),
        "vencido": validacion.get('vencido', False),
        "fecha_carga": cert_info['fecha_carga']
    }


@app.delete("/api/certificado/{empresa_id}")
async def eliminar_certificado(empresa_id: str):
    """
    Elimina el certificado cargado (por seguridad)
    """
    if empresa_id in CERTIFICADOS_CACHE:
        del CERTIFICADOS_CACHE[empresa_id]
        return {"ok": True, "mensaje": "Certificado eliminado"}
    
    return {"ok": False, "mensaje": "No había certificado configurado"}


# Manejo de errores global
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "ok": False,
            "error": str(exc),
            "mensaje": "Error interno del servidor"
        }
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
