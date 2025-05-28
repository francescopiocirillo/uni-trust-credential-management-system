import base64
import os
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class CryptoUtils:

    """
    Metodi per ottenere chiave privata e pubblica
    """
    @staticmethod
    def get_private_key() -> RSAPrivateKey:
        """
        Restituisce una chiave privata RSA
        :return: la chiave privata RSA
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key

    @staticmethod
    def get_public_key(private_key: rsa.RSAPrivateKey) -> RSAPublicKey:
        """
        Restituisce una chiave pubblica RSA corrispondente alla chiave
        privata fornita
        :param private_key: la chiave privata RSA della quale ottenere la corrispondente chiave pubblica
        :return: la chiave pubblica RSA corrispondente
        """
        public_key = private_key.public_key()
        return public_key

    """
    Metodi per la comunicazione asimmettrica (methods for asymmetric communication)
    """

    @staticmethod
    def encrypt_message_with_public_key(public_key: rsa.RSAPublicKey, message: str) -> bytes:
        """
        Codifica un messaggio usando la chiave pubblica fornita.
        La chiave pubblica dovrebbe essere quella del destinatario per garantire la segretezza.
        :param public_key: la chiave pubblica da usare per crittografare il messaggio
        :param message: il messaggio da criptare in formato stringa
        :return: il messaggio criptato in formato bytes
        """
        message_bytes = message.encode('utf-8')
        ciphertext = public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def decrypt_message_with_private_key(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> Optional[str]:
        """
        Decodifica un ciphertext usando la chiave privata fornita.
        La chiave privata dovrebbe essere quella del destinatario per garantire la segretezza.
        :param private_key: la chiave privata da usare per la decriptazione del ciphertext
        :param ciphertext: il ciphertext da decriptare
        :return: il messaggio decriptato in formato stringa oppure None se sono state sollevate eccezioni
        """
        try:
            decrypted_message = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_message.decode('utf-8')
        except Exception as e:
            return None

    @staticmethod
    def sign_message_with_private_key(private_key: rsa.RSAPrivateKey, message: str) -> bytes:
        """
        Crea la firma del messaggio ottenuta con la chiave privata fornita.
        Il messaggio viene sottoposto ad hashing e il digest viene criptato.
        La chiave privata dovrebbe essere quella del mittente per garantire integrità.
        :param private_key: la chiave privata da usare per firmare l'hash del messaggio
        :param message: il messaggio del quale si desidera creare la firma
        :return: la firma del messaggio
        """
        message_bytes = message.encode('utf-8')
        signature = private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_message_with_public_key(public_key: rsa.RSAPublicKey, signature: bytes, message: str) -> bool:
        """
        Verifica se il messaggio corrisponde alla firma realizzata con la chiave privata corrispondente
        alla chiave pubblica fornita come parametro.
        :param public_key: la chiave pubblica del mittente per verificare l'integrità del messaggio
        :param signature: la firma del messaggio fornito
        :param message: il messaggio del quale verificare l'integrità per mezzo della firma
        :return: True se la verifica è andata a buon fine, False altrimenti
        """
        message_bytes = message.encode('utf-8')
        try:
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

    @staticmethod
    def rsa_public_key_to_pem(public_key) -> str:
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')

    @staticmethod
    def pem_to_rsa_public_key(pem_str: str):
        pem_bytes = pem_str.encode('utf-8')  # Convert string to bytes
        public_key = serialization.load_pem_public_key(
            pem_bytes,
            backend=default_backend()
        )
        return public_key

    @staticmethod
    def generate_nonce(length: int = 32) -> str:
        """
        Genera un nonce crittograficamente sicuro.
        :param length: la lunghezza del nonce in byte
        :return: una stringa base64-url-safe che rappresenta il nonce
        """
        random_bytes = os.urandom(length)
        nonce = base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('utf-8')
        return nonce