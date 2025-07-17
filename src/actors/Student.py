import base64
import json
from typing import Optional, Any

from src.actors.CertifiedCommunicatingParty import CertifiedCommunicatingParty
from src.actors.StudentInfo import StudentInfo
from src.utils.CryptoUtils import CryptoUtils


class Student(CertifiedCommunicatingParty):
    """
    Rappresenta uno studente certificato che può partecipare a una comunicazione sicura.
    """

    def __init__(self,
                 party_id: str,

                 matricola_casa: str,
                 matricola_ospitante: str,
                 nome: str,
                 cognome: str,
                 email_casa: str,
                 email_ospitante: str,
                 data_di_nascita: str,
                 codice_corso_di_laurea: str,
                 nome_corso_di_laurea: str,
                 cfu_totali_conseguiti: int,
                 media_voti: float,

                 public_key: Optional[str] = None,
                 private_key: Optional[str] = None):
        """
       Inizializza un oggetto Student con le informazioni anagrafiche, accademiche e crittografiche.

       Args:
           party_id (str): Identificativo univoco del partecipante nella rete.
           matricola_casa (str): Matricola dell'università di origine.
           matricola_ospitante (str): Matricola presso l'università ospitante.
           nome (str): Nome dello studente.
           cognome (str): Cognome dello studente.
           email_casa (str): Email istituzionale dell'università di origine.
           email_ospitante (str): Email istituzionale dell'università ospitante.
           data_di_nascita (str): Data di nascita dello studente (formato: gg/mm/aaaa).
           codice_corso_di_laurea (str): Codice identificativo del corso di laurea.
           nome_corso_di_laurea (str): Nome completo del corso di laurea.
           cfu_totali_conseguiti (int): Numero totale di CFU ottenuti.
           media_voti (float): Media dei voti dello studente.
           public_key (Optional[str]): Chiave pubblica per la comunicazione sicura (in formato stringa).
           private_key (Optional[str]): Chiave privata per la comunicazione sicura (in formato stringa).
       """
        super().__init__(party_id=party_id, public_key=public_key, private_key=private_key)
        self.student_info = StudentInfo(matricola_casa, matricola_ospitante, nome, cognome, email_casa,
                                       email_ospitante, data_di_nascita, codice_corso_di_laurea,
                                       nome_corso_di_laurea, cfu_totali_conseguiti, media_voti)

    def introduce(self):
        self.student_info.introduce()

    def communicate(self, message: str) -> bytes:
        print(f"{self.student_info.nome} {self.student_info.cognome} sta inviando un messaggio criptato...")
        return self.send_encrypted_message_symmetric_encryption(message)

    def ask_for_student_info_certificate(self) -> bytes:
        message = "INFO REQUEST"
        return self.send_encrypted_message_symmetric_encryption(message)

    def receive_student_info_certificate(self, encrypted_data: bytes) -> None:
        data = CryptoUtils.decrypt_and_verify_message_symmetric_encryption(encrypted_data, self.symmetric_encryption_information)
        data = json.loads(data)
        merkle_tree_root_signature = data["merkle_tree_root_signature"].encode("utf-8")
        tree = json.loads(data["tree"])
        student_university_information = [merkle_tree_root_signature, tree]
        self.set_student_university_information(student_university_information)

    def set_student_university_information(self, student_university_information: Any) -> None:
        self.student_university_information = student_university_information

    def receive_request_info(self, request: bytes) -> Any:
        pass
