'''
Autore: Anis Ravera
Data: 27/10/2026
Titolo: HTTP Signature
'''
import  base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


class DigitalSignature:
    # Costruttore
    def __init__(self, nomeFile):
        self.nomeFile = nomeFile
    
    # Funzione per leggere fisicamente il file .pem in formato binario
    def leggiChiavePrivata(self):
        with open(self.nomeFile, 'rb') as file: # 'rb' "read binary"
            contenuto_chiave = file.read()
        
        # "Prendo" la chiave privata e la trasformo in un oggetto chiave RSA 
        privateKey = serialization.load_pem_private_key(
            contenuto_chiave,
            password = None # non è stata specificata alcuna password
        )
        return privateKey
    
    # Funzione per generare la firma matematica
    def generaFirma(self, testoFirmato):
        key = self.leggiChiavePrivata()
        
        # The algorithm to use for signing must be rsa-sha256 and PKCS1v15 for padding
        firma = key.sign ( 
            testoFirmato.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        # converto in base64, così da avere dati binari in testo
        return base64.b64encode(firma).decode('utf-8') # b64encode(sign(digest header content)
    
# Classe creata per validare la firma del server come da richiesta:
# Even if it is not mandatory, your client could validate 
# the server signature (available in the Signature response header)
class SignatureValidate:
    # Costruttore
    def __init__(self, nomeFile_Pubblico):
        self.nomeFile = nomeFile_Pubblico
    
    # Funzione per leggere fisicamente il file .pem in formato binario
    def leggiChiavePubblica(self):
        with open(self.nomeFile, 'rb') as file: # 'rb' "read binary"
            contenuto_chiave = file.read()
            
         # "Prendo" la chiave privata e la trasformo in un oggetto chiave RSA 
        publicKey = serialization.load_pem_public_key(
            contenuto_chiave
        )
        return publicKey

    def verificaChiavePubblica(self, testoFirmato, firma_base64):
        key = self.leggiChiavePubblica()
        
        firma = base64.b64decode(firma_base64)
        
        try:
            # Validazione matematica con try & except per le eccezioni
            key.verify(
                firma,
                testoFirmato.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True # Firma valida
        except InvalidSignature:
            return False # Firma errata