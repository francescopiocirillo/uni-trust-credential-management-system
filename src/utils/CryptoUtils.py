import base64
import os
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.padding import PaddingContext
from cryptography.hazmat.primitives import padding



class CryptoUtils:

    """
        Metodi per la comunicazione asimmettrica (methods for asymmetric communication)
    """

    # Metodi per ottenere chiave privata e pubblica

    @staticmethod
    def get_private_key() -> str:
        """
        Restituisce una chiave privata RSA
        :return: la chiave privata RSA
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return CryptoUtils.rsa_private_key_to_pem(private_key)

    @staticmethod
    def get_public_key(private_key: str) -> str:
        """
        Restituisce una chiave pubblica RSA corrispondente alla chiave
        privata fornita
        :param private_key: la chiave privata RSA della quale ottenere la corrispondente chiave pubblica
        :return: la chiave pubblica RSA corrispondente
        """
        private_key = CryptoUtils.pem_to_rsa_private_key(private_key)
        public_key = private_key.public_key()
        return CryptoUtils.rsa_public_key_to_pem(public_key)

    @staticmethod
    def encrypt_message_with_public_key(public_key: str, message: str) -> bytes:
        """
        Codifica un messaggio usando la chiave pubblica fornita.
        La chiave pubblica dovrebbe essere quella del destinatario per garantire la segretezza.
        :param public_key: la chiave pubblica da usare per crittografare il messaggio
        :param message: il messaggio da criptare in formato stringa
        :return: il messaggio criptato in formato bytes
        """
        public_key = CryptoUtils.pem_to_rsa_public_key(public_key)
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
    def decrypt_message_with_private_key(private_key: str, ciphertext: bytes) -> Optional[str]:
        """
        Decodifica un ciphertext usando la chiave privata fornita.
        La chiave privata dovrebbe essere quella del destinatario per garantire la segretezza.
        :param private_key: la chiave privata da usare per la decriptazione del ciphertext
        :param ciphertext: il ciphertext da decriptare
        :return: il messaggio decriptato in formato stringa oppure None se sono state sollevate eccezioni
        """
        private_key = CryptoUtils.pem_to_rsa_private_key(private_key)
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
    def sign_message_with_private_key(private_key: str, message: str) -> bytes:
        """
        Crea la firma del messaggio ottenuta con la chiave privata fornita.
        Il messaggio viene sottoposto ad hashing e il digest viene criptato.
        La chiave privata dovrebbe essere quella del mittente per garantire integrità.
        :param private_key: la chiave privata da usare per firmare l'hash del messaggio
        :param message: il messaggio del quale si desidera creare la firma
        :return: la firma del messaggio
        """
        private_key = CryptoUtils.pem_to_rsa_private_key(private_key)
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
    def verify_message_with_public_key(public_key: str, signature: bytes, message: str) -> bool:
        """
        Verifica se il messaggio corrisponde alla firma realizzata con la chiave privata corrispondente
        alla chiave pubblica fornita come parametro.
        :param public_key: la chiave pubblica del mittente per verificare l'integrità del messaggio
        :param signature: la firma del messaggio fornito
        :param message: il messaggio del quale verificare l'integrità per mezzo della firma
        :return: True se la verifica è andata a buon fine, False altrimenti
        """
        public_key = CryptoUtils.pem_to_rsa_public_key(public_key)
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

    """
    Metodi per la conversione chiave/stringa
    """

    @staticmethod
    def rsa_public_key_to_pem(public_key: RSAPublicKey) -> str:
        """
        Converte una chiave pubblica RSA in una stringa PEM.
        Questo formato è utile per la memorizzazione o la trasmissione della chiave.
        :param public_key: la chiave pubblica RSA da convertire
        :return: la chiave pubblica in formato PEM come stringa
        """
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')

    @staticmethod
    def pem_to_rsa_public_key(pem_str: str) -> RSAPublicKey:
        """
        Converte una stringa PEM in una chiave pubblica RSA.
        :param pem_str: la chiave pubblica in formato PEM come stringa
        :return: la chiave pubblica RSA ottenuta dal PEM
        """
        pem_bytes = pem_str.encode('utf-8')  # Converti la stringa in bytes
        public_key = serialization.load_pem_public_key(
            pem_bytes,
            backend=default_backend()
        )
        return public_key

    @staticmethod
    def rsa_private_key_to_pem(private_key: RSAPrivateKey, password: Optional[bytes] = None) -> str:
        """
        Converte una chiave privata RSA in una stringa PEM.
        :param private_key: la chiave privata RSA da convertire
        :param password: opzionale password per criptare la chiave PEM (in bytes). Se None, la chiave non sarà criptata.
        :return: la chiave privata in formato PEM come stringa
        """
        if password is not None:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()

        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        return pem_bytes.decode('utf-8')

    @staticmethod
    def pem_to_rsa_private_key(pem_str: str, password: Optional[bytes] = None) -> RSAPrivateKey:
        """
        Converte una stringa PEM in una chiave privata RSA.
        :param pem_str: la chiave privata in formato PEM come stringa
        :param password: password in bytes, se la chiave è criptata (default None)
        :return: la chiave privata RSA
        """
        pem_bytes = pem_str.encode('utf-8')
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=password,
            backend=default_backend()
        )
        return private_key

    """
    Metodi per la comunicazione simmetrice
    """

    @staticmethod
    def encrypt_message_with_symmetric_cipher(message: bytes, cipher: Cipher, padder: PaddingContext) -> bytes:
        padded_message = padder.update(message) + padder.finalize()

        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_message) + encryptor.finalize()

        return cipher_text

    @staticmethod
    def decrypt_message_with_symmetric_cipher(cipher_text: bytes, cipher: Cipher) -> str:
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

        return decrypted_message.decode()

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

    @staticmethod
    def session_key_to_key_str(session_key: bytes) -> str:
        # Serializzazione
        key_b64 = base64.b64encode(session_key).decode('utf-8')
        return key_b64

    @staticmethod
    def key_str_to_session_key(key_b64: str) -> bytes:
        # Deserializzazione
        session_key = base64.b64decode(key_b64.encode('utf-8'))
        return session_key