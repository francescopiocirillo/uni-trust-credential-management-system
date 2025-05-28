import json
from typing import Optional, Dict

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from src.certificate_authority.CertificateAuthority import CertificateAuthority
from src.certificate_authority.CertificateOfIdentity import CertificateOfIdentity
from src.utils.CryptoUtils import CryptoUtils


class CertifiedCommunicatingParty:
    """
    Rappresenta un'entità che è stata certificata da una certificate authority e che può comunicare
    con altre entità certificate effettuando una verifica dell'identità dell'interlocutore e creando
    una comunicazione crittografata simmetrica.
    """

    def __init__(self,
                 party_id: str = None,
                 public_key: Optional[RSAPublicKey] = None,
                 private_key: Optional[RSAPrivateKey] = None,
                 certificate_of_identity: Optional['CertificateOfIdentity'] = None,
                 public_key_ring: Optional[Dict[str, RSAPublicKey]] = None):
        """
        Inizializza un'istanza di CertifiedCommunicatingParty.

        Args:
            party_id (str): Un identificatore univoco per l'entità certificata.
            public_key (Optional[str]): La chiave crittografica pubblica dell'entità (in formato stringa).
            private_key (Optional[str]): La chiave crittografica privata dell'entità (in formato stringa).
            certificate_of_identity (Optional[CertificateOfIdentity]): Il certificato d'identità dell'entità.
            public_key_ring (Optional[Dict[str, RSAPublicKey]]): Dizionario che associa gli ID delle entità
                alle loro chiavi pubbliche RSA. Se non specificato, viene inizializzato come dizionario vuoto.
        """
        self.party_id: str = party_id
        self.public_key: Optional[RSAPublicKey] = public_key
        self.private_key: Optional[RSAPrivateKey] = private_key
        self.certificate_of_identity: Optional['CertificateOfIdentity'] = certificate_of_identity
        self.session_key: str = ""
        self.public_key_ring: Dict[str, RSAPublicKey] = public_key_ring if public_key_ring is not None else {}
        self.interlocutor_information: Optional[CertificateOfIdentity] = None

    def set_up_asymmetric_communication_keys(self):
        self.private_key = CryptoUtils.get_private_key()
        self.public_key = CryptoUtils.get_public_key(self.private_key)

    def ask_for_certificate_of_identity(self, certificate_authority: CertificateAuthority) -> None:
        self.certificate_of_identity = certificate_authority.issue_certificate(
            id_party_to_certify=self.party_id,
            public_key_party_to_certify=self.public_key
        )

    def send_certificate_of_identity(self) -> CertificateOfIdentity:
        return self.certificate_of_identity

    def receive_certificate_of_identity(self, interlocutor_certificate_of_identity: CertificateOfIdentity) -> None:
        self.interlocutor_information.certificate_of_identity = interlocutor_certificate_of_identity

    def secure_key_distribution_protocol_send_first_message(self) -> bytes:
        secure_key_distribution_protocol_first_message_json = {
            "id": self.party_id,
            "nonce_1": CryptoUtils.generate_nonce(),
            "nonce_2": "",
        }
        secure_key_distribution_protocol_first_message_string = json.dumps(secure_key_distribution_protocol_first_message_json, separators=(',', ':'), sort_keys=True)

        public_key_of_the_certified_party = CryptoUtils.pem_to_rsa_public_key(self.interlocutor_information.public_key_of_the_certified_party)

        ciphertext = CryptoUtils.encrypt_message_with_public_key(
            public_key=public_key_of_the_certified_party,
            message=secure_key_distribution_protocol_first_message_string
        )
        return ciphertext

    def secure_key_distribution_protocol_receive_first_message(self, ciphertext: bytes) -> None:
        secure_key_distribution_protocol_first_message_string = CryptoUtils.decrypt_message_with_private_key(
            private_key=self.private_key,
            ciphertext=ciphertext,
        )
        secure_key_distribution_protocol_first_message_json = json.loads(secure_key_distribution_protocol_first_message_string)
        if self.interlocutor_information.id_of_the_certified_party == secure_key_distribution_protocol_first_message_json["id"]:
            pass

    def set_up_symmetric_communication(self) -> str:
        pass

    def send_encrypted_message(self) -> None:
        pass

    def receive_encrypted_message(self) -> None:
        pass

    def encrypt_message(self) -> None:
        pass

    def decrypt_message(self) -> None:
        pass



# Main per test
if __name__ == "__main__":
    pass