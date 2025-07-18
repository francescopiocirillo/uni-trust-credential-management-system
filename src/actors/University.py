import base64
import json

from cryptography.hazmat.primitives import padding

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

    def add_student_info(self, party_id: str, student_info: StudentInfo) -> None:
        self.student_infos[party_id] = student_info

    def get_student_info(self, party_id: str) -> StudentInfo:
        return self.student_infos[party_id]

    def remove_student_info(self, party_id: str) -> StudentInfo:
        return self.student_infos.pop(party_id)

    def receive_student_info_certificate_request(self, request: bytes):
        info_request = self.receive_encrypted_message_symmetric_encryption(request)
        if info_request != "INFO REQUEST":
            return None

        student_info = self.get_student_info(self.symmetric_encryption_information.get_interlocutor())
        data_list = student_info.to_data_list()
        merkle_tree = MerkleTree(data_list)
        merkle_tree_root_signature = CryptoUtils.sign_message_with_private_key(self.asymmetric_encryption_information.private_key, merkle_tree.root)
        #print(merkle_tree.tree)
        payload = {
            "merkle_tree_root_signature": base64.b64encode(merkle_tree_root_signature).decode("utf-8"),
            "tree": json.dumps(merkle_tree.tree),
        }
        payload = json.dumps(payload)
        ciphertext = CryptoUtils.autenthicate_and_encrypt_message_symmetric_encryption(payload, self.symmetric_encryption_information)
        self.symmetric_encryption_information.set_padder(
            padding.PKCS7(128).padder()  # Pad del messaggio alla dimensione di un blocco AES
        )
        return ciphertext

    def request_info(self, request: str) -> bytes:
        ciphertext = CryptoUtils.autenthicate_and_encrypt_message_symmetric_encryption(request, self.symmetric_encryption_information)
        self.symmetric_encryption_information.set_padder(
            padding.PKCS7(128).padder()  # Pad del messaggio alla dimensione di un blocco AES
        )
        return ciphertext

    def receive_info_requested(self, encrypted_info: bytes, public_key: str) -> bytes:
        decrypted_info = CryptoUtils.decrypt_and_verify_message_symmetric_encryption(encrypted_info, self.symmetric_encryption_information)
        decrypted_info = json.loads(decrypted_info)
        print(decrypted_info)
        data = decrypted_info["data"]
        proof = json.loads(decrypted_info["proof"])
        signature = base64.b64decode(decrypted_info["signature"])
        root = decrypted_info["root"]

        reply = ""
        if CryptoUtils.verify_message_with_public_key(public_key, signature, root):
            if MerkleTree.verify_data_with_proof(data, proof, root):
                reply = "ACK"
            else:
                reply = "NACK"
        else:
            reply = "NACK"

        reply = CryptoUtils.autenthicate_and_encrypt_message_symmetric_encryption(reply, self.symmetric_encryption_information)
        return reply