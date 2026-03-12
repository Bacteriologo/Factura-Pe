"""
Firma digital XAdES-BES para comprobantes electrónicos SUNAT
"""
from lxml import etree
from signxml import XMLSigner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import base64


def firmar_xml(xml_string: str, cert_data: dict) -> str:
    """
    Firma un XML con XAdES-BES
    
    Args:
        xml_string: XML a firmar
        cert_data: {
            'private_key': objeto clave privada,
            'certificate': objeto certificado X.509
        }
    
    Returns:
        XML firmado como string
    """
    try:
        # Parsear XML
        root = etree.fromstring(xml_string.encode('utf-8'))
        
        # Encontrar el nodo UBLExtensions/UBLExtension/ExtensionContent
        namespaces = {
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }
        
        ext_content = root.find('.//ext:UBLExtensions/ext:UBLExtension/ext:ExtensionContent', namespaces)
        
        if ext_content is None:
            raise ValueError("No se encontró ExtensionContent en el XML")
        
        # Crear el firmador
        signer = XMLSigner(
            method='enveloped',
            signature_algorithm='rsa-sha256',
            digest_algorithm='sha256',
            c14n_algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
        )
        
        # Serializar clave y certificado
        private_key_pem = cert_data['private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        cert_pem = cert_data['certificate'].public_bytes(
            encoding=serialization.Encoding.PEM
        )
        
        # Firmar
        signed_root = signer.sign(
            root,
            key=private_key_pem,
            cert=cert_pem
        )
        
        # Convertir a string
        xml_firmado = etree.tostring(
            signed_root,
            pretty_print=True,
            xml_declaration=True,
            encoding='UTF-8'
        ).decode('utf-8')
        
        return xml_firmado
        
    except Exception as e:
        raise Exception(f"Error al firmar XML: {str(e)}")


def cargar_certificado_p12(archivo_bytes: bytes, password: str) -> dict:
    """
    Carga un certificado .p12/.pfx
    
    Args:
        archivo_bytes: Contenido del archivo .p12
        password: Contraseña del certificado
    
    Returns:
        {
            'private_key': clave privada,
            'certificate': certificado X.509,
            'ca_certs': certificados CA (opcional)
        }
    """
    try:
        private_key, certificate, ca_certs = pkcs12.load_key_and_certificates(
            archivo_bytes,
            password.encode('utf-8'),
            backend=default_backend()
        )
        
        return {
            'private_key': private_key,
            'certificate': certificate,
            'ca_certs': ca_certs or []
        }
        
    except Exception as e:
        raise Exception(f"Error al cargar certificado: {str(e)}")


def validar_certificado(cert_data: dict) -> dict:
    """
    Valida un certificado digital
    
    Returns:
        {
            'valido': bool,
            'emisor': str,
            'sujeto': str,
            'fecha_inicio': str,
            'fecha_fin': str,
            'vencido': bool
        }
    """
    try:
        cert = cert_data['certificate']
        
        fecha_inicio = cert.not_valid_before_utc
        fecha_fin = cert.not_valid_after_utc
        ahora = datetime.utcnow()
        
        return {
            'valido': True,
            'emisor': cert.issuer.rfc4514_string(),
            'sujeto': cert.subject.rfc4514_string(),
            'fecha_inicio': fecha_inicio.isoformat(),
            'fecha_fin': fecha_fin.isoformat(),
            'vencido': ahora > fecha_fin,
            'dias_restantes': (fecha_fin - ahora).days if ahora < fecha_fin else 0
        }
        
    except Exception as e:
        return {
            'valido': False,
            'error': str(e)
        }


def extraer_ruc_de_certificado(cert_data: dict) -> str:
    """Extrae el RUC del certificado digital"""
    try:
        cert = cert_data['certificate']
        sujeto = cert.subject.rfc4514_string()
        
        # El RUC suele estar en el CN (Common Name) del certificado
        # Formato típico: "CN=20123456789 - NOMBRE EMPRESA"
        for attr in sujeto.split(','):
            if 'CN=' in attr:
                cn_value = attr.split('CN=')[1].strip()
                # Extraer solo números del inicio
                ruc = ''.join(filter(str.isdigit, cn_value.split('-')[0].strip()))
                if len(ruc) == 11:  # RUC tiene 11 dígitos
                    return ruc
        
        return ""
        
    except:
        return ""
