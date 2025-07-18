import base64
import json
from heapq import merge
from typing import Optional, Any

from cryptography.hazmat.primitives import padding

from src.actors.CertifiedCommunicatingParty import CertifiedCommunicatingParty
from src.actors.StudentInfo import StudentInfo
from src.utils.CryptoUtils import CryptoUtils
from src.utils.MerkleTree import MerkleTree


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
        merkle_tree_root_signature = base64.b64decode(data["merkle_tree_root_signature"])
        tree = json.loads(data["tree"])
        student_university_information = [merkle_tree_root_signature, tree]
        #print(student_university_information[1])
        self.set_student_university_information(student_university_information)

    def set_student_university_information(self, student_university_information: Any) -> None:
        self.student_university_information = student_university_information

    def receive_request_info_and_send_info(self, request: bytes) -> Any:
        decrypted_message = CryptoUtils.decrypt_and_verify_message_symmetric_encryption(request, self.symmetric_encryption_information)
        data = self.student_university_information[1][0]
        index = 0
        for idx, item in enumerate(data):
            if item.startswith(decrypted_message):
                index = idx
                break
        merkle_tree = MerkleTree.from_root_and_tree(self.student_university_information[1][-1][0], self.student_university_information[1])
        merkle_proof = MerkleTree.get_merkle_proof(merkle_tree, index)
        #print(merkle_proof)
        payload = {
            "data": data[index],
            "proof": json.dumps(merkle_proof),
            "signature": base64.b64encode(self.student_university_information[0]).decode("utf-8"),
            "root": merkle_tree.root
        }
        payload = json.dumps(payload)
        ciphertext = CryptoUtils.autenthicate_and_encrypt_message_symmetric_encryption(payload, self.symmetric_encryption_information)
        self.symmetric_encryption_information.set_padder(
            padding.PKCS7(128).padder()  # Pad del messaggio alla dimensione di un blocco AES
        )
        return ciphertext

    def receive_feedback_on_info_student(self, ack_nack: bytes) -> None:
        ack_nack = CryptoUtils.decrypt_and_verify_message_symmetric_encryption(ack_nack, self.symmetric_encryption_information)
        print("Il certificato delle informazioni sullo studente è stato ")
        if ack_nack == "ACK":
            print("ACCETTATO")
        else:
            print("RIFIUTATO")