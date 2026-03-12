"""
Generador de XMLs según formato UBL 2.1 de SUNAT
Soporta: Facturas, Boletas, Notas de Crédito, Notas de Débito
"""
from lxml import etree
from datetime import datetime
import hashlib


def generar_xml_comprobante(datos: dict) -> str:
    """
    Genera XML UBL 2.1 para factura o boleta
    
    datos = {
        'tipo': 'FACTURA' | 'BOLETA',
        'serie': 'F001' | 'B001',
        'numero': 123,
        'fecha_emision': '2026-03-12',
        'hora_emision': '14:30:00',
        'moneda': 'PEN',
        
        'emisor': {
            'ruc': '20123456789',
            'nombre': 'MI EMPRESA SAC',
            'nombre_comercial': 'Mi Empresa',
            'ubigeo': '150101',
            'direccion': 'Av. Lima 123',
            'urbanizacion': 'Centro',
            'distrito': 'Lima',
            'provincia': 'Lima',
            'departamento': 'Lima',
            'pais': 'PE'
        },
        
        'cliente': {
            'tipo_doc': '6' (RUC) | '1' (DNI),
            'num_doc': '20987654321',
            'nombre': 'CLIENTE SAC'
        },
        
        'items': [
            {
                'codigo': 'P001',
                'descripcion': 'Producto 1',
                'cantidad': 2,
                'unidad': 'NIU',
                'precio_unitario': 10.0,  # SIN IGV
                'precio_venta': 11.8,      # CON IGV
                'valor_total': 20.0,       # cantidad * precio_unitario
                'igv': 3.6,
                'total': 23.6
            }
        ],
        
        'totales': {
            'gravadas': 20.0,       # Base imponible
            'igv': 3.6,
            'total': 23.6
        }
    }
    """
    
    tipo = datos['tipo']
    codigo_tipo = '01' if tipo == 'FACTURA' else '03'  # 01=Factura, 03=Boleta
    
    # Namespaces UBL
    nsmap = {
        None: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
        'cac': "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
        'cbc': "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        'ccts': "urn:un:unece:uncefact:documentation:2",
        'ds': "http://www.w3.org/2000/09/xmldsig#",
        'ext': "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
        'qdt': "urn:oasis:names:specification:ubl:schema:xsd:QualifiedDatatypes-2",
        'udt': "urn:un:unece:uncefact:data:specification:UnqualifiedDataTypesSchemaModule:2",
        'xsi': "http://www.w3.org/2001/XMLSchema-instance"
    }
    
    # Raíz
    root = etree.Element("Invoice", nsmap=nsmap)
    
    # UBL Extensions (para firma)
    ext_elem = etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtensions")
    ext_item = etree.SubElement(ext_elem, "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtension")
    ext_content = etree.SubElement(ext_item, "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}ExtensionContent")
    
    # Placeholder para firma (se llenará después)
    # etree.SubElement(ext_content, "Signature")
    
    # Versión UBL
    etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}UBLVersionID").text = "2.1"
    etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}CustomizationID").text = "2.0"
    
    # ID del comprobante
    numero_completo = f"{datos['serie']}-{str(datos['numero']).zfill(8)}"
    etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID").text = numero_completo
    
    # Fecha y hora
    etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}IssueDate").text = datos['fecha_emision']
    etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}IssueTime").text = datos['hora_emision']
    
    # Tipo de comprobante
    inv_type = etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}InvoiceTypeCode")
    inv_type.set("listID", codigo_tipo)
    inv_type.text = codigo_tipo
    
    # Moneda
    etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}DocumentCurrencyCode").text = datos.get('moneda', 'PEN')
    
    # === EMISOR ===
    emisor_data = datos['emisor']
    accounting_supplier = etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}AccountingSupplierParty")
    supplier_party = etree.SubElement(accounting_supplier, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}Party")
    
    # ID emisor (RUC)
    party_id = etree.SubElement(supplier_party, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}PartyIdentification")
    party_id_elem = etree.SubElement(party_id, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID")
    party_id_elem.set("schemeID", "6")  # 6 = RUC
    party_id_elem.text = emisor_data['ruc']
    
    # Nombre emisor
    party_name = etree.SubElement(supplier_party, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}PartyName")
    etree.SubElement(party_name, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}Name").text = emisor_data.get('nombre_comercial', emisor_data['nombre'])
    
    # Dirección emisor
    postal_addr = etree.SubElement(supplier_party, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}PostalAddress")
    etree.SubElement(postal_addr, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID").text = emisor_data.get('ubigeo', '150101')
    etree.SubElement(postal_addr, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}StreetName").text = emisor_data.get('direccion', '')
    etree.SubElement(postal_addr, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}CityName").text = emisor_data.get('distrito', 'Lima')
    etree.SubElement(postal_addr, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}CountrySubentity").text = emisor_data.get('departamento', 'Lima')
    etree.SubElement(postal_addr, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}District").text = emisor_data.get('distrito', 'Lima')
    
    country = etree.SubElement(postal_addr, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}Country")
    etree.SubElement(country, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}IdentificationCode").text = emisor_data.get('pais', 'PE')
    
    # Nombre legal emisor
    party_legal = etree.SubElement(supplier_party, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}PartyLegalEntity")
    etree.SubElement(party_legal, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}RegistrationName").text = emisor_data['nombre']
    
    # === CLIENTE ===
    cliente_data = datos['cliente']
    accounting_customer = etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}AccountingCustomerParty")
    customer_party = etree.SubElement(accounting_customer, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}Party")
    
    # ID cliente
    customer_id = etree.SubElement(customer_party, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}PartyIdentification")
    customer_id_elem = etree.SubElement(customer_id, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID")
    customer_id_elem.set("schemeID", cliente_data.get('tipo_doc', '1'))  # 1=DNI, 6=RUC
    customer_id_elem.text = cliente_data.get('num_doc', '-')
    
    # Nombre cliente
    customer_legal = etree.SubElement(customer_party, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}PartyLegalEntity")
    etree.SubElement(customer_legal, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}RegistrationName").text = cliente_data.get('nombre', 'Cliente Final')
    
    # === ITEMS / LÍNEAS ===
    for idx, item_data in enumerate(datos['items'], start=1):
        invoice_line = etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}InvoiceLine")
        etree.SubElement(invoice_line, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID").text = str(idx)
        
        # Cantidad
        quantity = etree.SubElement(invoice_line, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}InvoicedQuantity")
        quantity.set("unitCode", item_data.get('unidad', 'NIU'))
        quantity.text = f"{item_data['cantidad']:.2f}"
        
        # Valor total línea (sin IGV)
        line_ext_amount = etree.SubElement(invoice_line, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}LineExtensionAmount")
        line_ext_amount.set("currencyID", datos.get('moneda', 'PEN'))
        line_ext_amount.text = f"{item_data['valor_total']:.2f}"
        
        # Pricing (precio unitario sin IGV)
        pricing = etree.SubElement(invoice_line, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}PricingReference")
        alt_cond_price = etree.SubElement(pricing, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}AlternativeConditionPrice")
        price_amount = etree.SubElement(alt_cond_price, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}PriceAmount")
        price_amount.set("currencyID", datos.get('moneda', 'PEN'))
        price_amount.text = f"{item_data['precio_venta']:.2f}"
        etree.SubElement(alt_cond_price, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}PriceTypeCode").text = "01"  # Precio unitario incluye IGV
        
        # IGV del item
        tax_total = etree.SubElement(invoice_line, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxTotal")
        tax_amount = etree.SubElement(tax_total, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxAmount")
        tax_amount.set("currencyID", datos.get('moneda', 'PEN'))
        tax_amount.text = f"{item_data['igv']:.2f}"
        
        tax_subtotal = etree.SubElement(tax_total, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxSubtotal")
        taxable_amount = etree.SubElement(tax_subtotal, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxableAmount")
        taxable_amount.set("currencyID", datos.get('moneda', 'PEN'))
        taxable_amount.text = f"{item_data['valor_total']:.2f}"
        
        tax_amount2 = etree.SubElement(tax_subtotal, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxAmount")
        tax_amount2.set("currencyID", datos.get('moneda', 'PEN'))
        tax_amount2.text = f"{item_data['igv']:.2f}"
        
        tax_category = etree.SubElement(tax_subtotal, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxCategory")
        etree.SubElement(tax_category, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID").text = "S"  # S=IGV
        etree.SubElement(tax_category, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}Percent").text = "18.00"
        etree.SubElement(tax_category, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxExemptionReasonCode").text = "10"  # Gravado - Operación Onerosa
        
        tax_scheme = etree.SubElement(tax_category, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxScheme")
        etree.SubElement(tax_scheme, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID").text = "1000"  # IGV
        etree.SubElement(tax_scheme, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}Name").text = "IGV"
        etree.SubElement(tax_scheme, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxTypeCode").text = "VAT"
        
        # Descripción del item
        item_elem = etree.SubElement(invoice_line, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}Item")
        etree.SubElement(item_elem, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}Description").text = item_data['descripcion']
        
        sellers_item_id = etree.SubElement(item_elem, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}SellersItemIdentification")
        etree.SubElement(sellers_item_id, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID").text = item_data.get('codigo', 'PROD')
        
        # Precio unitario (sin IGV)
        price = etree.SubElement(invoice_line, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}Price")
        price_amount2 = etree.SubElement(price, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}PriceAmount")
        price_amount2.set("currencyID", datos.get('moneda', 'PEN'))
        price_amount2.text = f"{item_data['precio_unitario']:.2f}"
    
    # === TOTALES ===
    totales = datos['totales']
    
    # Total IGV
    tax_total_doc = etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxTotal")
    tax_amount_doc = etree.SubElement(tax_total_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxAmount")
    tax_amount_doc.set("currencyID", datos.get('moneda', 'PEN'))
    tax_amount_doc.text = f"{totales['igv']:.2f}"
    
    tax_subtotal_doc = etree.SubElement(tax_total_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxSubtotal")
    taxable_amount_doc = etree.SubElement(tax_subtotal_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxableAmount")
    taxable_amount_doc.set("currencyID", datos.get('moneda', 'PEN'))
    taxable_amount_doc.text = f"{totales['gravadas']:.2f}"
    
    tax_amount_doc2 = etree.SubElement(tax_subtotal_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxAmount")
    tax_amount_doc2.set("currencyID", datos.get('moneda', 'PEN'))
    tax_amount_doc2.text = f"{totales['igv']:.2f}"
    
    tax_category_doc = etree.SubElement(tax_subtotal_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxCategory")
    tax_scheme_doc = etree.SubElement(tax_category_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}TaxScheme")
    etree.SubElement(tax_scheme_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}ID").text = "1000"
    etree.SubElement(tax_scheme_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}Name").text = "IGV"
    etree.SubElement(tax_scheme_doc, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxTypeCode").text = "VAT"
    
    # Monetary Total
    legal_monetary = etree.SubElement(root, "{urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2}LegalMonetaryTotal")
    
    line_ext_amount_total = etree.SubElement(legal_monetary, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}LineExtensionAmount")
    line_ext_amount_total.set("currencyID", datos.get('moneda', 'PEN'))
    line_ext_amount_total.text = f"{totales['gravadas']:.2f}"
    
    tax_inclusive_amount = etree.SubElement(legal_monetary, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}TaxInclusiveAmount")
    tax_inclusive_amount.set("currencyID", datos.get('moneda', 'PEN'))
    tax_inclusive_amount.text = f"{totales['total']:.2f}"
    
    payable_amount = etree.SubElement(legal_monetary, "{urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2}PayableAmount")
    payable_amount.set("currencyID", datos.get('moneda', 'PEN'))
    payable_amount.text = f"{totales['total']:.2f}"
    
    # Convertir a string
    xml_string = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding='UTF-8').decode('utf-8')
    
    return xml_string


def calcular_hash_cpe(xml_string: str) -> str:
    """Calcula hash SHA256 del XML (para código QR y validación)"""
    return hashlib.sha256(xml_string.encode('utf-8')).hexdigest()
