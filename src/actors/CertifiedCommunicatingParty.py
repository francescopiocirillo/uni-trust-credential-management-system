import base64
import json
import os
from typing import Optional, Dict

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.certificate_authority.CertificateAuthority import CertificateAuthority
from src.certificate_authority.CertificateOfIdentity import CertificateOfIdentity
from src.main import session_info_encrypted
from src.utils.AsymmetricEncryptionInformation import AsymmetricEncryptionInformation
from src.utils.CryptoUtils import CryptoUtils
from src.utils.SymmetricEncryptionInformation import SymmetricEncryptionInformation


class CertifiedCommunicatingParty:
    """
    Rappresenta un'entità che è stata certificata da una certificate authority e che può comunicare
    con altre entità certificate effettuando una verifica dell'identità dell'interlocutore e creando
    una comunicazione crittografata simmetrica.
    """

    def __init__(self,
                 party_id: str = None,
                 public_key: Optional[str] = None,
                 private_key: Optional[str] = None,
                 certificate_of_identity: Optional['CertificateOfIdentity'] = None):
        """
        Inizializza un'istanza di CertifiedCommunicatingParty.

        Args:
            party_id (str): Un identificatore univoco per l'entità certificata.
            public_key (Optional[str]): La chiave crittografica pubblica dell'entità (in formato stringa).
            private_key (Optional[str]): La chiave crittografica privata dell'entità (in formato stringa).
            certificate_of_identity (Optional[CertificateOfIdentity]): Il certificato d'identità dell'entità.
        """
        self.party_id: str = party_id

        self.asymmetric_encryption_information = AsymmetricEncryptionInformation()
        self.asymmetric_encryption_information.set_public_key(public_key)
        self.asymmetric_encryption_information.set_private_key(private_key)
        self.asymmetric_encryption_information.set_certificate_of_identity(certificate_of_identity)

        self.symmetric_encryption_information = SymmetricEncryptionInformation()

    def set_up_asymmetric_communication_keys(self):
        self.asymmetric_encryption_information.set_private_key( CryptoUtils.get_private_key() )
        self.asymmetric_encryption_information.set_public_key( CryptoUtils.get_public_key( self.asymmetric_encryption_information.get_private_key() ) )

    def ask_for_certificate_of_identity(self, certificate_authority: CertificateAuthority) -> None:
        self.asymmetric_encryption_information.set_certificate_of_identity(
            certificate_authority.issue_certificate(
                id_party_to_certify=self.party_id,
                public_key_party_to_certify=self.asymmetric_encryption_information.get_public_key()
            )
        )

    def send_certificate_of_identity(self) -> CertificateOfIdentity:
        return self.asymmetric_encryption_information.get_certificate_of_identity()

    def receive_certificate_of_identity(self, interlocutor_certificate_of_identity: CertificateOfIdentity) -> None:
        self.asymmetric_encryption_information.set_interlocutor_information(interlocutor_certificate_of_identity)

    def secure_key_distribution_protocol_send_first_message(self) -> bytes:
        # si crea un payload con la propria identità e un nonce da mandare all'interlocutore
        self.symmetric_encryption_information.set_nonce_sent(
            CryptoUtils.generate_nonce()
        )
        secure_key_distribution_protocol_first_message_json = {
            "id": self.party_id,
            "nonce_1": self.symmetric_encryption_information.get_nonce_sent(),
            "nonce_2": "",
        }
        secure_key_distribution_protocol_first_message_string = json.dumps(secure_key_distribution_protocol_first_message_json, separators=(',', ':'), sort_keys=True)

        # il payload viene criptato e inviato
        ciphertext = CryptoUtils.encrypt_message_with_public_key(
            public_key=self.asymmetric_encryption_information.get_interlocutor_information().public_key_of_the_certified_party,
            message=secure_key_distribution_protocol_first_message_string
        )
        return ciphertext

    def secure_key_distribution_protocol_receive_first_message_and_send_second_message(self, ciphertext: bytes) -> Optional[bytes]:
        if ciphertext is None:
            self.asymmetric_encryption_information.set_interlocutor_information(None)
            return None

        # si decripta il ciphertext ricevuto dall'interlocutore e lo si converte in json
        secure_key_distribution_protocol_first_message_string = CryptoUtils.decrypt_message_with_private_key(
            private_key=self.asymmetric_encryption_information.get_private_key(),
            ciphertext=ciphertext,
        )
        secure_key_distribution_protocol_first_message_json = json.loads(secure_key_distribution_protocol_first_message_string)

        # se l'identità nel messaggio non corrisponde a quella del certificato ricevuto allora la comunicazione è da interrompere
        if self.asymmetric_encryption_information.get_interlocutor_information().id_of_the_certified_party != secure_key_distribution_protocol_first_message_json["id"]:
            self.asymmetric_encryption_information.set_interlocutor_information(None)
            return None

        # si legge il nonce ricevuto per poterlo rimandare, inoltre si crea un proprio nonce originale da inviare
        nonce_received = secure_key_distribution_protocol_first_message_json["nonce_1"]
        self.symmetric_encryption_information.set_nonce_sent(
            CryptoUtils.generate_nonce()
        )
        secure_key_distribution_protocol_second_message_json = {
            "id": "",
            "nonce_1": nonce_received,
            "nonce_2": self.symmetric_encryption_information.get_nonce_sent()
        }
        secure_key_distribution_protocol_second_message_string = json.dumps(secure_key_distribution_protocol_second_message_json, separators=(',', ':'), sort_keys=True)

        # si cripta il nuovo payload e lo si invia
        ciphertext = CryptoUtils.encrypt_message_with_public_key(
            public_key=self.asymmetric_encryption_information.get_interlocutor_information().public_key_of_the_certified_party,
            message=secure_key_distribution_protocol_second_message_string
        )
        return ciphertext

    def secure_key_distribution_protocol_receive_second_message_and_send_third_message(self, ciphertext: bytes) -> Optional[bytes]:
        if ciphertext is None:
            self.asymmetric_encryption_information.set_interlocutor_information(None)
            return None

        # si decripta il ciphertext ricevuto dall'interlocutore e lo si converte in json
        secure_key_distribution_protocol_second_message_string = CryptoUtils.decrypt_message_with_private_key(
            private_key=self.asymmetric_encryption_information.get_private_key(),
            ciphertext=ciphertext,
        )
        secure_key_distribution_protocol_second_message_json = json.loads(
            secure_key_distribution_protocol_second_message_string)

        # se il nonce ricevuto non corrisponde a quello inviato allora la comunicazione è da interrompere
        if self.symmetric_encryption_information.get_nonce_sent() != secure_key_distribution_protocol_second_message_json["nonce_1"]:
            self.asymmetric_encryption_information.set_interlocutor_information(None)
            return None

        self.symmetric_encryption_information.set_handshake_completed_true()
        self.symmetric_encryption_information.set_nonce_sent(None)

        # si legge il nonce ricevuto per poterlo rimandare, inoltre si crea un proprio nonce originale da inviare
        nonce_received = secure_key_distribution_protocol_second_message_json["nonce_2"]
        secure_key_distribution_protocol_third_message_json = {
            "id": "",
            "nonce_1": "",
            "nonce_2": nonce_received
        }
        secure_key_distribution_protocol_third_message_string = json.dumps(
            secure_key_distribution_protocol_second_message_json, separators=(',', ':'), sort_keys=True)

        # si cripta il nuovo payload e lo si invia
        ciphertext = CryptoUtils.encrypt_message_with_public_key(
            public_key=self.asymmetric_encryption_information.get_interlocutor_information().public_key_of_the_certified_party,
            message=secure_key_distribution_protocol_third_message_string
        )
        return ciphertext

    def secure_key_distribution_protocol_receive_third_message(self, ciphertext: bytes) -> None:
        if ciphertext is None:
            self.asymmetric_encryption_information.set_interlocutor_information(None)
            return None

        # si decripta il ciphertext ricevuto dall'interlocutore e lo si converte in json
        secure_key_distribution_protocol_third_message_string = CryptoUtils.decrypt_message_with_private_key(
            private_key=self.asymmetric_encryption_information.get_private_key(),
            ciphertext=ciphertext,
        )
        secure_key_distribution_protocol_third_message_json = json.loads(
            secure_key_distribution_protocol_third_message_string)

        # se il nonce ricevuto non corrisponde a quello inviato allora la comunicazione è da interrompere
        if self.symmetric_encryption_information.get_nonce_sent() != secure_key_distribution_protocol_third_message_json["nonce_2"]:
            self.asymmetric_encryption_information.set_interlocutor_information(None)
            return None

        self.symmetric_encryption_information.set_handshake_completed_true()
        self.symmetric_encryption_information.set_nonce_sent(None)
        return None

    def set_up_symmetric_communication(self) -> None:
        key = os.urandom(32)
        iv = os.urandom(16)

        self.symmetric_encryption_information.set_cipher(
            Cipher(algorithms.AES(key), modes.CBC(iv))
        )
        self.symmetric_encryption_information.set_session_key( CryptoUtils.session_key_to_key_str(key) )
        self.symmetric_encryption_information.set_iv(
            CryptoUtils.session_key_to_key_str(iv)
        )
        self.symmetric_encryption_information.set_padder(
            padding.PKCS7(128).padder()  # Pad del messaggio alla dimensione di un blocco AES
        )

    def send_information_symmetric_communication(self):
        session_info = {
            "session_key": self.symmetric_encryption_information.get_session_key(),
            "iv": self.symmetric_encryption_information.get_iv(),
        }
        session_info = json.dumps(session_info, separators=(',', ':'), sort_keys=True)

        session_info_encrypted = self.encrypt_message_asymmetric_encryption(session_info)
        return session_info_encrypted

    def set_up_symmetric_communication_from_info_received(self, session_info: str) -> None:
        session_info = json.loads(session_info)

        self.symmetric_encryption_information.set_session_key( session_info["session_key"] )
        self.symmetric_encryption_information.set_iv(
            session_info["iv"]
        )

        key = CryptoUtils.key_str_to_session_key( self.symmetric_encryption_information.get_session_key() )
        iv = CryptoUtils.key_str_to_session_key(self.symmetric_encryption_information.get_iv())

        self.symmetric_encryption_information.set_cipher(
            Cipher(algorithms.AES(key), modes.CBC(iv))
        )
        self.symmetric_encryption_information.set_padder(
            padding.PKCS7(128).padder()  # Pad del messaggio alla dimensione di un blocco AES
        )
        return None

    def encrypt_message_asymmetric_encryption(self, message: str) -> bytes:
        signature = CryptoUtils.sign_message_with_private_key(self.asymmetric_encryption_information.get_private_key(), message)

        encrypted_message = CryptoUtils.encrypt_message_with_public_key(
            self.asymmetric_encryption_information.get_interlocutor_information().public_key_of_the_certified_party,
            message
        )

        # codifica in base64
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        encrypted_b64 = base64.b64encode(encrypted_message).decode('utf-8')

        # preparazione payload da inviare
        payload = {
            'signature': signature_b64,
            'ciphertext': encrypted_b64
        }
        return json.dumps(payload).encode('utf-8')

    def decrypt_message_asymmetric_encryption(self, ciphertext: bytes) -> Optional[str]:
        try:
            # Parse JSON e decode base64
            payload = json.loads(ciphertext.decode('utf-8'))
            signature = base64.b64decode(payload['signature'])
            ciphertext = base64.b64decode(payload['ciphertext'])

            # decriptazione del messaggio
            decrypted_message = CryptoUtils.decrypt_message_with_private_key(self.asymmetric_encryption_information.get_private_key(), ciphertext)
            if decrypted_message is None:
                return None

            # 3. verifica della firma
            verified = CryptoUtils.verify_message_with_public_key(
                self.asymmetric_encryption_information.get_interlocutor_information().public_key_of_the_certified_party,
                signature,
                decrypted_message
            )
            return decrypted_message if verified else None
        except Exception:
            return None

    def send_encrypted_message_symmetric(self, message: str) -> bytes:
        return CryptoUtils.encrypt_message_with_symmetric_cipher(message.encode("utf-8"), self.symmetric_encryption_information.cipher, self.symmetric_encryption_information.padder)

    def end_symmetric_communication(self) -> bytes:
        end_message_encrypted = CryptoUtils.encrypt_message_with_symmetric_cipher("End of Communication", self.symmetric_encryption_information.cipher, self.symmetric_encryption_information.padder)
        self.symmetric_encryption_information = SymmetricEncryptionInformation()
        return end_message_encrypted

    def receive_encrypted_message(self) -> None:
        pass

    def encrypt_message(self) -> None:
        pass

    def decrypt_message(self) -> None:
        pass



# Main per test
if __name__ == "__main__":
    pass