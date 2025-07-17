from src.actors.CertifiedCommunicatingParty import CertifiedCommunicatingParty
from typing import Optional


class University(CertifiedCommunicatingParty):
    """
    Rappresenta un'università certificata capace di comunicare con altre entità
    utilizzando protocolli crittografici sicuri.
    """

    def __init__(self,
                 party_id: str,
                 nome: str,
                 nazione: str,
                 codice_universita: str,
                 email_contatto: str,
                 public_key: Optional[str] = None,
                 private_key: Optional[str] = None):
        """
        Inizializza un oggetto University.

        Args:
            party_id (str): Identificatore univoco dell’università.
            nome (str): Nome completo dell’università.
            nazione (str): Paese in cui si trova l’università.
            codice_universita (str): Codice identificativo (es. Erasmus, ministeriale...).
            email_contatto (str): Email ufficiale di contatto.
            public_key (Optional[str]): Chiave pubblica per la comunicazione sicura.
            private_key (Optional[str]): Chiave privata per la comunicazione sicura.
        """
        super().__init__(party_id=party_id, public_key=public_key, private_key=private_key)

        self.nome = nome
        self.nazione = nazione
        self.codice_universita = codice_universita
        self.email_contatto = email_contatto

    def describe(self):
        """
        Stampa le informazioni principali dell’università.
        """
        print(f"{self.nome} ({self.codice_universita}) - {self.nazione}")
        print(f"Contatto: {self.email_contatto}")
