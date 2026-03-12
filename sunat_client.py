"""
Cliente SOAP para comunicación con webservices de SUNAT
"""
from zeep import Client
from zeep.transports import Transport
from requests import Session
import base64
import zipfile
from io import BytesIO
from lxml import etree


class SunatClient:
    """Cliente para interactuar con webservices de SUNAT"""
    
    # URLs de SUNAT
    URLS = {
        'beta': {
            'factura': 'https://e-beta.sunat.gob.pe/ol-ti-itcpfegem-beta/billService?wsdl',
            'guia': 'https://e-beta.sunat.gob.pe/ol-ti-itemision-guia-gem-beta/billService?wsdl',
            'retenciones': 'https://e-beta.sunat.gob.pe/ol-ti-itemision-otroscpe-gem-beta/billService?wsdl'
        },
        'produccion': {
            'factura': 'https://e-factura.sunat.gob.pe/ol-ti-itcpfegem/billService?wsdl',
            'guia': 'https://e-guiaremision.sunat.gob.pe/ol-ti-itemision-guia-gem/billService?wsdl',
            'retenciones': 'https://e-factura.sunat.gob.pe/ol-ti-itemision-otroscpe-gem/billService?wsdl'
        }
    }
    
    def __init__(self, ruc_emisor: str, usuario_sol: str, clave_sol: str, ambiente: str = 'beta'):
        """
        Args:
            ruc_emisor: RUC del emisor
            usuario_sol: Usuario SOL (ej: MODDATOS)
            clave_sol: Clave SOL
            ambiente: 'beta' o 'produccion'
        """
        self.ruc_emisor = ruc_emisor
        self.usuario_sol = usuario_sol
        self.clave_sol = clave_sol
        self.ambiente = ambiente
        
        # URL del webservice
        self.wsdl_url = self.URLS.get(ambiente, {}).get('factura')
        
        # Configurar sesión con autenticación
        session = Session()
        session.auth = (f"{ruc_emisor}{usuario_sol}", clave_sol)
        
        # Cliente SOAP
        transport = Transport(session=session, timeout=30)
        self.client = Client(wsdl=self.wsdl_url, transport=transport)
    
    
    def enviar_comprobante(self, xml_firmado: str, nombre_archivo: str) -> dict:
        """
        Envía un comprobante a SUNAT
        
        Args:
            xml_firmado: XML firmado digitalmente
            nombre_archivo: Nombre del archivo (ej: "20123456789-01-F001-00000001")
        
        Returns:
            {
                'success': bool,
                'codigo': str,
                'mensaje': str,
                'cdr': str (base64),
                'cdr_xml': str,
                'hash_cdr': str
            }
        """
        try:
            # 1. Comprimir XML en ZIP
            zip_bytes = self._comprimir_xml_a_zip(xml_firmado, nombre_archivo)
            zip_base64 = base64.b64encode(zip_bytes).decode('utf-8')
            
            # 2. Enviar a SUNAT
            response = self.client.service.sendBill(
                fileName=f"{nombre_archivo}.zip",
                contentFile=zip_base64
            )
            
            # 3. Procesar respuesta
            if hasattr(response, 'applicationResponse'):
                cdr_base64 = response.applicationResponse
                cdr_zip = base64.b64decode(cdr_base64)
                cdr_xml = self._extraer_cdr_de_zip(cdr_zip)
                
                # Parsear CDR para obtener resultado
                resultado = self._parsear_cdr(cdr_xml)
                
                return {
                    'success': True,
                    'codigo': resultado.get('codigo', '0'),
                    'mensaje': resultado.get('mensaje', 'Aceptado'),
                    'estado': resultado.get('estado', 'ACEPTADO'),
                    'cdr_base64': cdr_base64,
                    'cdr_xml': cdr_xml,
                    'hash_cdr': resultado.get('hash', ''),
                    'observaciones': resultado.get('observaciones', [])
                }
            else:
                return {
                    'success': False,
                    'codigo': 'ERROR',
                    'mensaje': 'No se recibió CDR de SUNAT',
                    'estado': 'ERROR'
                }
        
        except Exception as e:
            error_msg = str(e)
            
            # Parsear errores comunes de SUNAT
            codigo_error = self._extraer_codigo_error(error_msg)
            
            return {
                'success': False,
                'codigo': codigo_error,
                'mensaje': error_msg,
                'estado': 'RECHAZADO'
            }
    
    
    def consultar_ticket(self, ticket: str) -> dict:
        """
        Consulta el estado de un ticket (para resúmenes diarios)
        
        Args:
            ticket: Número de ticket retornado por SUNAT
        
        Returns:
            Estado del procesamiento
        """
        try:
            response = self.client.service.getStatus(ticket=ticket)
            
            if hasattr(response, 'statusCode'):
                return {
                    'success': True,
                    'codigo': response.statusCode,
                    'estado': self._mapear_estado_ticket(response.statusCode)
                }
            
            return {'success': False, 'mensaje': 'Respuesta inválida'}
            
        except Exception as e:
            return {'success': False, 'mensaje': str(e)}
    
    
    def _comprimir_xml_a_zip(self, xml_content: str, nombre_archivo: str) -> bytes:
        """Comprime el XML en formato ZIP como lo requiere SUNAT"""
        zip_buffer = BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr(f"{nombre_archivo}.xml", xml_content.encode('utf-8'))
        
        return zip_buffer.getvalue()
    
    
    def _extraer_cdr_de_zip(self, zip_bytes: bytes) -> str:
        """Extrae el XML del CDR del ZIP retornado por SUNAT"""
        try:
            with zipfile.ZipFile(BytesIO(zip_bytes), 'r') as zip_file:
                # El CDR suele ser el único archivo en el ZIP
                nombres = zip_file.namelist()
                if nombres:
                    return zip_file.read(nombres[0]).decode('utf-8')
            return ""
        except:
            return ""
    
    
    def _parsear_cdr(self, cdr_xml: str) -> dict:
        """
        Parsea el CDR (Constancia de Recepción) de SUNAT
        
        Returns:
            {
                'codigo': str (código de respuesta),
                'mensaje': str,
                'estado': 'ACEPTADO' | 'RECHAZADO' | 'OBSERVADO',
                'hash': str,
                'observaciones': [str]
            }
        """
        try:
            root = etree.fromstring(cdr_xml.encode('utf-8'))
            
            # Namespaces del CDR
            ns = {
                'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
                'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'
            }
            
            # Código de respuesta
            codigo_elem = root.find('.//cbc:ResponseCode', ns)
            codigo = codigo_elem.text if codigo_elem is not None else '0'
            
            # Descripción
            descripcion_elem = root.find('.//cbc:Description', ns)
            descripcion = descripcion_elem.text if descripcion_elem is not None else ''
            
            # Hash del documento
            hash_elem = root.find('.//cbc:DocumentHash', ns)
            hash_doc = hash_elem.text if hash_elem is not None else ''
            
            # Determinar estado
            estado = 'ACEPTADO' if codigo == '0' else 'RECHAZADO'
            
            # Observaciones (si hay)
            observaciones = []
            for note in root.findall('.//cbc:Note', ns):
                if note.text:
                    observaciones.append(note.text)
            
            if observaciones and codigo == '0':
                estado = 'OBSERVADO'
            
            return {
                'codigo': codigo,
                'mensaje': descripcion,
                'estado': estado,
                'hash': hash_doc,
                'observaciones': observaciones
            }
            
        except Exception as e:
            return {
                'codigo': 'ERROR',
                'mensaje': f'Error al parsear CDR: {str(e)}',
                'estado': 'ERROR',
                'hash': '',
                'observaciones': []
            }
    
    
    def _extraer_codigo_error(self, mensaje_error: str) -> str:
        """Extrae el código de error de SUNAT del mensaje"""
        # Errores comunes de SUNAT
        errores = {
            '2800': 'El contribuyente no está activo',
            '2801': 'El contribuyente no está habilitado',
            '2802': 'El usuario SOL no existe',
            '2803': 'Clave SOL incorrecta',
            '1033': 'Certificado revocado o vencido',
            '2324': 'El archivo ZIP está corrupto',
            '2325': 'El XML no corresponde al estándar',
            '2335': 'El comprobante fue informado previamente',
            '4000': 'Firma digital inválida'
        }
        
        for codigo, desc in errores.items():
            if codigo in mensaje_error:
                return codigo
        
        return 'ERROR_DESCONOCIDO'
    
    
    def _mapear_estado_ticket(self, codigo: str) -> str:
        """Mapea código de estado de ticket a texto legible"""
        estados = {
            '0': 'PROCESADO',
            '98': 'EN_PROCESO',
            '99': 'PROCESADO_CON_ERRORES'
        }
        return estados.get(codigo, 'DESCONOCIDO')


# Códigos de error SUNAT más comunes
CODIGOS_ERROR_SUNAT = {
    '0': 'Aceptado',
    '100': 'La operación ha sido aceptada',
    '2000': 'Comprobante observado',
    '2800': 'El contribuyente no está activo',
    '2801': 'El contribuyente no está habilitado para emitir electrónicamente',
    '2802': 'El usuario SOL no existe',
    '2803': 'Clave SOL incorrecta',
    '2324': 'El archivo ZIP está corrupto',
    '2325': 'El comprobante electrónico contiene errores',
    '2335': 'El comprobante fue informado previamente',
    '4000': 'La firma digital es inválida',
    '4001': 'Certificado revocado',
    '4002': 'Certificado vencido'
}
