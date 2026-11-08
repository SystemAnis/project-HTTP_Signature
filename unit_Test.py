'''
Autore: Anis Ravera
Titolo: Unit test del client HTTP Signature

I test sono auto-contenuti: generano una coppia di chiavi RSA temporanea,
quindi NON serve avere le chiavi reali nel repository e NON viene fatta
nessuna chiamata di rete.
'''
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from digest import (
    build_authorization_header,
    build_body,
    build_digest_header,
    extract_signature,
)
from digit_signature import DigitalSignature, SignatureValidate


class DigestUnitTests(unittest.TestCase):
    """Verifica la costruzione del body e dell'header Digest."""

    def test_body_json_compatto(self):
        payload = {"author": "Your Name", "code": "YOUR_CODE_HERE"}
        body = build_body(payload)

        # Il body deve essere JSON valido e senza spazi nei separatori
        self.assertEqual(json.loads(body), payload)
        self.assertNotIn(": ", body)
        self.assertNotIn(", ", body)

    def test_digest_sha256_base64(self):
        body = '{"author":"Your Name","code":"YOUR_CODE_HERE"}'
        digest_header = build_digest_header(body)

        digest_atteso = base64.b64encode(
            hashlib.sha256(body.encode("utf-8")).digest()
        ).decode("utf-8")

        self.assertEqual(digest_header, f"SHA-256={digest_atteso}")

        # SHA-256 produce 32 byte (256 bit)
        byte_crudi = base64.b64decode(digest_atteso)
        self.assertEqual(len(byte_crudi), 32)

    def test_authorization_header(self):
        header = build_authorization_header("Zm9v", "client1")

        self.assertIn('keyId="client1"', header)
        self.assertIn('algorithm="rsa-sha256"', header)
        self.assertIn('signature="Zm9v"', header)
        self.assertIn('headers="digest"', header)

    def test_estrazione_firma_server(self):
        header = (
            'Signature keyId="server1",algorithm="rsa-sha256",'
            'signature="Zm9v",headers="digest"'
        )
        self.assertEqual(extract_signature(header), "Zm9v")
        self.assertIsNone(extract_signature('Signature keyId="server1"'))


class SignatureUnitTests(unittest.TestCase):
    """Verifica firma e validazione con una coppia di chiavi RSA temporanea."""

    @classmethod
    def setUpClass(cls):
        cls._tmp_dir = tempfile.TemporaryDirectory()
        base_dir = Path(cls._tmp_dir.name)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        cls.private_key_path = base_dir / "client_private_key.pem"
        cls.public_key_path = base_dir / "server_public_key.pem"

        cls.private_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cls.public_key_path.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    @classmethod
    def tearDownClass(cls):
        cls._tmp_dir.cleanup()

    def test_firma_round_trip(self):
        digest_header = build_digest_header(
            build_body({"author": "Your Name", "code": "YOUR_CODE_HERE"})
        )

        signer = DigitalSignature(str(self.private_key_path))
        firma_base64 = signer.generaFirma(digest_header)

        # La firma deve essere una stringa Base64 non vuota
        self.assertIsInstance(firma_base64, str)
        self.assertGreater(len(base64.b64decode(firma_base64)), 0)

        validator = SignatureValidate(str(self.public_key_path))
        self.assertTrue(validator.verificaChiavePubblica(digest_header, firma_base64))

    def test_digest_manomesso_non_valido(self):
        digest_header = build_digest_header(
            build_body({"author": "Your Name", "code": "YOUR_CODE_HERE"})
        )

        signer = DigitalSignature(str(self.private_key_path))
        firma_base64 = signer.generaFirma(digest_header)

        validator = SignatureValidate(str(self.public_key_path))
        self.assertFalse(
            validator.verificaChiavePubblica(digest_header + "manomesso", firma_base64)
        )


if __name__ == '__main__':
    unittest.main()
