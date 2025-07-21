import json
import time

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.certificate_authority.CertificateOfIdentity import CertificateOfIdentity
from src.utils.CryptoUtils import CryptoUtils

VERBOSE_MESSAGE_SIZE = False
VERBOSE_MESSAGE_TIME = False

class CertificateAuthority:

    certificate_counter: int = 0

    def __init__(self, id: str):
        self.id: str = id
        self.private_key: str = CryptoUtils.get_private_key()
        self.public_key: str = CryptoUtils.get_public_key(self.private_key)
        self.issued_certificates: dict[str, CertificateOfIdentity] = {}
        self.revocation_list: set[str] = set()

    def issue_certificate(self, id_party_to_certify: str, public_key_party_to_certify: str) -> CertificateOfIdentity:
        start_time = time.perf_counter()

        CertificateAuthority.certificate_counter += 1
        certificate_id = f"cert_{CertificateAuthority.certificate_counter}"
        certificate_to_sign_dict = {
            "id_of_the_certificate": certificate_id,
            "id_of_the_certificate_authority": self.id,
            "public_key_of_the_certificate_authority": self.public_key,
            "id_of_the_certified_party": id_party_to_certify,
            "public_key_of_the_certified_party": public_key_party_to_certify
        }
        certificate_to_sign = json.dumps(certificate_to_sign_dict, separators=(',', ':'), sort_keys=True)

        signed_certificate = CryptoUtils.sign_message_with_private_key(
            private_key=self.private_key,
            message=certificate_to_sign
        )
        certificate_of_identity = CertificateOfIdentity(
            id_of_the_certificate=certificate_id,
            id_of_the_certificate_authority=self.id,
            public_key_of_the_certificate_authority=self.public_key,
            id_of_the_certified_party=id_party_to_certify,
            public_key_of_the_certified_party=public_key_party_to_certify,
            signed_certificate=signed_certificate
        )

        if VERBOSE_MESSAGE_SIZE:
            print("Informazioni sul certificato di identitàf")
            print("Dimensione certificato: ", len(certificate_to_sign))
            print("Dimensione firma: ", len(signed_certificate))

        # aggiunta del certificato al dizionario di quelli creati
        self.issued_certificates[certificate_id] = certificate_of_identity

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000  # tempo in millisecondi

        if VERBOSE_MESSAGE_TIME:
            print("Tempo per la creazione di un certificato da parte della CA: ", latency_ms)

        return certificate_of_identity


    def revoke_certificate(self, id: str) -> None:
        if id in self.issued_certificates:
            del self.issued_certificates[id]
            self.revocation_list.add(id)
            print(f"Certificato con ID {id} revocato.")
        else:
            print(f"Certificate con ID {id} non trovato o già revocato.")

    def verify_certificate(self, certificate_id: str) -> bool:
        pass
