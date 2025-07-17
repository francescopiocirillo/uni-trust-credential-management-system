from src.actors.CertifiedCommunicatingParty import CertifiedCommunicatingParty
from typing import Optional, Dict

from src.actors.StudentInfo import StudentInfo
from src.utils.CryptoUtils import CryptoUtils
from src.utils.MerkleTree import MerkleTree


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
        self.student_infos: Dict[str, StudentInfo] = {}

    def describe(self):
        """
        Stampa le informazioni principali dell’università.
        """
        print(f"{self.nome} ({self.codice_universita}) - {self.nazione}")
        print(f"Contatto: {self.email_contatto}")

    def add_student_info(self, student_info: StudentInfo) -> None:
        self.student_infos.update(student_info.matricola_casa, student_info)

    def get_student_info(self, matricola: str) -> StudentInfo:
        return self.student_infos[matricola]

    def remove_student_info(self, matricola: str) -> StudentInfo:
        return self.student_infos.pop(matricola)

    def receive_student_info_certificate_request(self, request: bytes):
        info_request = self.receive_encrypted_message_symmetric_encryption(request)
        if info_request != "INFO REQUEST":
            return None

        student_info = self.get_student_info(self.symmetric_encryption_information.get_interlocutor())
        data_list = student_info.to_data_list()
        merkle_tree = MerkleTree(data_list)
        merkle_tree_root_signature = CryptoUtils.sign_message_with_private_key(self.private_key, merkle_tree.root)
        return merkle_tree_root_signature, merkle_tree.tree
