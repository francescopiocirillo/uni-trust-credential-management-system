import json

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.certificate_authority.CertificateOfIdentity import CertificateOfIdentity
from src.utils.CryptoUtils import CryptoUtils


class CertificateAuthority:

    certificate_counter: int = 0

    def __init__(self, id: str):
        self.id: str = id
        self.private_key = CryptoUtils.get_private_key()
        self.public_key = CryptoUtils.get_public_key(self.private_key)
        self.issued_certificates: dict[str, CertificateOfIdentity] = {}
        self.revocation_list: set[str] = set()

    def issue_certificate(self, id_party_to_certify: str, public_key_party_to_certify: RSAPublicKey) -> CertificateOfIdentity:
        CertificateAuthority.certificate_counter += 1
        certificate_id = f"cert_{CertificateAuthority.certificate_counter}"
        certificate_to_sign_dict = {
            "id_of_the_certificate": certificate_id,
            "id_of_the_certificate_authority": self.id,
            "public_key_of_the_certificate_authority": CryptoUtils.rsa_public_key_to_pem(self.public_key),
            "id_of_the_certified_party": id_party_to_certify,
            "public_key_of_the_certified_party": CryptoUtils.rsa_public_key_to_pem(public_key_party_to_certify)
        }
        certificate_to_sign = json.dumps(certificate_to_sign_dict, separators=(',', ':'), sort_keys=True)

        certificate_of_identity = CertificateOfIdentity(
            id_of_the_certificate=certificate_id,
            id_of_the_certificate_authority=self.id,
            public_key_of_the_certificate_authority=CryptoUtils.rsa_public_key_to_pem(self.public_key),
            id_of_the_certified_party=id_party_to_certify,
            public_key_of_the_certified_party=CryptoUtils.rsa_public_key_to_pem(public_key_party_to_certify),
            signed_certificate=CryptoUtils.sign_message_with_private_key(
                private_key=self.private_key,
                message=certificate_to_sign
            )
        )

        # aggiunta del certificato al dizionario di quelli creati
        self.issued_certificates[certificate_id] = certificate_of_identity
        return certificate_of_identity


    def revoke_certificate(self, id: str) -> None:
        if id in self.issued_certificates:
            del self.issued_certificates[id]
            self.revocation_list.add(id)
            print(f"Certificate with ID {id} revoked.")
        else:
            print(f"Certificate with ID {id} not found or already revoked.")

    def verify_certificate(self, certificate_id: str) -> bool:
        pass
