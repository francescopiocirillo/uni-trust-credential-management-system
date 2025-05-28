from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class CertificateOfIdentity:
    """
    Rappresenta un Certificato di identità con attributi relativi all'identificazione e alle chiavi di crittografia.
    """

    def __init__(self,
                 id_of_the_certificate: str,
                 id_of_the_certificate_authority: str,
                 id_of_the_certified_party: str,
                 public_key_of_the_certificate_authority: str,
                 public_key_of_the_certified_party: str,
                 signed_certificate: bytes):
        """
        Inizializza un nuovo oggetto di tipo CertificateOfIdentity.

        Args:
            id_of_the_certificate (str): Identificativo univoco del certificato.
            id_of_the_certificate_authority (str): Identificativo della certificate authority
                                                    che ha rilasciato il certificato.
            id_of_the_certified_party (str): Identificativo dell'entità la cui identità
                                                è certificata dal certificato.
            public_key_of_the_certificate_authority (str): Chiave pubblica della certificate authority.
            public_key_of_the_certified_party (str): Chiave pubblica dell'entità comunicante.
            signed_certificate (str): La firma che del certificato.
        """
        self.id_of_the_certificate = id_of_the_certificate
        self.id_of_the_certificate_authority = id_of_the_certificate_authority
        self.id_of_the_certified_party = id_of_the_certified_party
        self.public_key_of_the_certificate_authority = public_key_of_the_certificate_authority
        self.public_key_of_the_certified_party = public_key_of_the_certified_party
        self.signed_certificate = signed_certificate

    def __repr__(self):
        """
        Fornisce una rappresentazione come stringa dell'oggetto CertificateOfIdentity,
        utile per il debugging.
        """
        return (f"CertificateOfIdentity("
                f"id_of_the_certificate='{self.id_of_the_certificate}', "
                f"id_of_the_certificate_authority='{self.id_of_the_certificate_authority}', "
                f"id_of_the_certified_party='{self.id_of_the_certified_party}', "
                f"public_key_of_the_certificate_authority='{self.public_key_of_the_certificate_authority}', "
                f"public_key_of_the_certified_party='{self.public_key_of_the_certified_party}', "
                f"signed_certificate='{self.signed_certificate}')")

    def __str__(self):
        """
        Fornisce una rappresentazione user-friendly come stringa dell'oggetto CertificateOfIdentity.
        """
        return (f"Certificate ID: {self.id_of_the_certificate}\n"
                f"Certificate Authority ID: {self.id_of_the_certificate_authority}\n"
                f"Certified Party ID: {self.id_of_the_certified_party}\n"
                f"CA Public Key: {self.public_key_of_the_certificate_authority[:20]}...\n" # Output troncato per la UX
                f"Party Public Key: {self.public_key_of_the_certified_party[:20]}...\n" # Output troncato per la UX
                f"Signed Certificate: {self.signed_certificate[:20]}...") # Output troncato per la UX

# Esempio di utilizz:
if __name__ == "__main__":
    cert = CertificateOfIdentity(
        id_of_the_certificate="cert123",
        id_of_the_certificate_authority="ca_org",
        id_of_the_certified_party="party_A",
        public_key_of_the_certificate_authority="-----BEGIN PUBLIC KEY CA...",
        public_key_of_the_certified_party="-----BEGIN PUBLIC KEY PARTY A...",
        signed_certificate="-----BEGIN SIGNED CERTIFICATE..."
    )

    print("--- Certificate Details ---")
    print(cert)

    print(f"\nCertificate ID (accessed directly): {cert.id_of_the_certificate}")

    print("\n--- Representation for Debugging ---")
    print(repr(cert))
