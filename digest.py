'''
Autore: Anis Ravera
Titolo: HTTP Signature Client

Client HTTP che firma il body della richiesta con RSA-SHA256 e valida
la firma restituita dal server nell'header "Signature".

Nota: URL e attempt-code reali NON sono versionati. Vengono letti dalle
variabili d'ambiente SIGNATURE_URL e ATTEMPT_CODE (vedi README.md).
'''
import base64
import hashlib
import json
import os

import requests

from digit_signature import DigitalSignature, SignatureValidate

# Placeholder: il valore reale va passato tramite la variabile SIGNATURE_URL
DEFAULT_URL = "https://example.com/api"
REQUEST_TIMEOUT = 10  # secondi


def build_body(payload: dict[str, str]) -> str:
    """Serializza il payload in JSON compatto, pronto per essere firmato."""
    # separators=(',', ':') evita spazi e virgole non voluti
    return json.dumps(payload, separators=(',', ':'))


def build_digest_header(body: str) -> str:
    """Calcola SHA-256 del body e lo codifica in Base64 per l'header Digest."""
    conversione_utf8 = body.encode('utf-8')
    hash_sha256 = hashlib.sha256(conversione_utf8).digest()
    digest = base64.b64encode(hash_sha256).decode('utf-8')
    return f"SHA-256={digest}"


def build_authorization_header(signature_base64: str, key_id: str = "client1") -> str:
    """Costruisce l'header Authorization con la firma RSA-SHA256."""
    return (
        f'Signature keyId="{key_id}",algorithm="rsa-sha256",'
        f'signature="{signature_base64}",headers="digest"'
    )


def extract_signature(signature_header: str) -> str | None:
    """Isola il valore di 'signature' dall'header Signature del server."""
    # Split semplice sull'inizio del parametro, senza ricorrere alle regex
    parti = signature_header.split('signature="')
    if len(parti) < 2:
        return None
    return parti[1].split('"')[0]


def print_response(response: requests.Response) -> None:
    """Stampa il dump completo della risposta del server."""
    print("==DUMP SERVER==")
    print(f"Status HTTP: {response.status_code}")

    print("Header:")
    for chiave, valore in response.headers.items():
        print(f"{chiave}: {valore} \n")

    print("Body:")
    print(response.text)


def verify_server_signature(response: requests.Response, public_key_path: str) -> None:
    """Valida la firma del server usando la sua chiave pubblica."""
    header_firma_server = response.headers.get("Signature")
    header_digest_server = response.headers.get("Digest")

    if not header_firma_server or not header_digest_server:
        print("Il server non ha restituito gli header 'Signature' o 'Digest' per la validazione.")
        return

    firma_estratta = extract_signature(header_firma_server)
    if not firma_estratta:
        print("Errore: impossibile isolare il parametro 'signature'.")
        return

    verifica_public_key = SignatureValidate(public_key_path)
    if verifica_public_key.verificaChiavePubblica(header_digest_server, firma_estratta):
        print("SUCCESSO: La firma del server è valida. Il mittente è certificato!")
    else:
        print("ERRORE: La firma del server NON è valida. Possibile manomissione.")


def main() -> int:
    # Configurazione tramite variabili d'ambiente: nessun dato sensibile nel repo
    url = os.environ.get("SIGNATURE_URL", DEFAULT_URL)
    author = os.environ.get("AUTHOR_NAME", "Your Name")
    attempt_code = os.environ.get("ATTEMPT_CODE", "YOUR_CODE_HERE")
    key_id = os.environ.get("KEY_ID", "client1")
    private_key_path = os.environ.get("CLIENT_PRIVATE_KEY", "client_private_key.pem")
    server_public_key_path = os.environ.get("SERVER_PUBLIC_KEY", "server_public_key.pem")

    persona = {
        "author": author,
        "code": attempt_code,
    }

    formato_testuale = build_body(persona)
    header_digest = build_digest_header(formato_testuale)

    # Genero la firma dell'header Digest con la chiave privata del client
    firma = DigitalSignature(private_key_path)
    firma_base64 = firma.generaFirma(header_digest)

    header_auth = build_authorization_header(firma_base64, key_id)

    headers = {
        "Content-Type": "application/json",  # il body è JSON
        "Digest": header_digest,             # impronta SHA-256 del body
        "Authorization": header_auth,        # firma RSA dell'header Digest
    }

    # Richiesta POST con timeout per evitare blocchi indefiniti
    try:
        risposta_post = requests.post(
            url,
            data=formato_testuale,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        print(f"ERRORE: richiesta HTTP fallita: {exc}")
        return 1

    print_response(risposta_post)

    print("\n NICE TO HAVE: Validazione della Firma del Server")
    verify_server_signature(risposta_post, server_public_key_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
