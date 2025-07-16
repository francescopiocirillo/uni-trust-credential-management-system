from typing import Optional, Dict

from src.certificate_authority.CertificateOfIdentity import CertificateOfIdentity


class AsymmetricEncryptionInformation:

    def __init__(self):
        """
        Inizializza un'istanza della classe AsymmetricEncryptionInformation.

        Attributes:
            public_key (Optional[str]): Chiave pubblica della parte che possiede queste informazioni.
            private_key (Optional[str]): Chiave privata della parte che possiede queste informazioni.
            certificate_of_identity (Optional[CertificateOfIdentity]): Certificato di identità della parte che possiede queste informazioni.
            public_key_ring (Dict[str, str]): Dizionario delle coppie identificativo/chiave privata degli interlocutori.
            interlocutor_information (Optional[CertificateOfIdentity]): Certificato di identità dell'interlocutore.
        """
        self.public_key: Optional[str] = None
        self.private_key: Optional[str] = None
        self.certificate_of_identity: Optional['CertificateOfIdentity'] = None
        self.public_key_ring: Dict[str, str] = {}
        self.interlocutor_information: Optional[CertificateOfIdentity] = None

    # Getters and Setters

    def get_public_key(self) -> Optional[str]:
        return self.public_key

    def set_public_key(self, key: str):
        self.public_key = key

    def get_private_key(self) -> Optional[str]:
        return self.private_key

    def set_private_key(self, key: str):
        self.private_key = key

    def get_certificate_of_identity(self) -> Optional[CertificateOfIdentity]:
        return self.certificate_of_identity

    def set_certificate_of_identity(self, cert: CertificateOfIdentity):
        self.certificate_of_identity = cert

    def add_to_public_key_ring(self, identifier: str, public_key: str):
        self.public_key_ring[identifier] = public_key

    def remove_from_public_key_ring(self, identifier: str) -> bool:
        if identifier in self.public_key_ring:
            del self.public_key_ring[identifier]
            return True
        return False

    def find_in_public_key_ring(self, identifier: str) -> Optional[str]:
        return self.public_key_ring.get(identifier)

    def get_interlocutor_information(self) -> Optional[CertificateOfIdentity]:
        return self.interlocutor_information

    def set_interlocutor_information(self, info: Optional[CertificateOfIdentity]):
        self.interlocutor_information = info
