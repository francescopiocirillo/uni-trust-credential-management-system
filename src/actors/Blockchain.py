class Blockchain:
    def __init__(self):
        # Inizializza il set vuoto chiamato CRL (Certificate Revocation List)
        self.crl = set()

    def aggiungi_a_crl(self, voce):
        """
        Aggiunge una nuova voce alla CRL.
        :param voce: stringa da aggiungere al set
        """
        if isinstance(voce, str):
            self.crl.add(voce)
        else:
            raise ValueError("Solo le stringhe possono essere aggiunte alla CRL.")

    def mostra_crl(self):
        """
        Ritorna una lista ordinata delle voci nella CRL.
        """
        return sorted(self.crl)

    def is_revoked(self, voce) -> bool:
        return voce in self.crl
