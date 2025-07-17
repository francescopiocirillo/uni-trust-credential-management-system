from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.padding import PaddingContext


class SymmetricEncryptionInformation:

    def __init__(self):
        self.handshake_completed: bool = False
        self.nonce_sent: Optional[str] = None
        self.cipher: Optional[Cipher] = None
        self.session_key: Optional[str] = None
        self.iv: Optional[str] = None
        self.padder: Optional[PaddingContext] = None
        self.mac_session_key: Optional[str] = None
        self.id_of_the_interlocutor: Optional[str] = None

    # Getters and Setters

    def get_session_key(self) -> Optional[str]:
        return self.session_key

    def set_session_key(self, key: str):
        self.session_key = key

    def is_handshake_completed(self) -> bool:
        return self.handshake_completed

    def set_handshake_completed_true(self):
        self.handshake_completed = True

    def set_handshake_completed_false(self):
        self.handshake_completed = False

    def get_nonce_sent(self) -> Optional[str]:
        return self.nonce_sent

    def set_nonce_sent(self, nonce: str):
        self.nonce_sent = nonce

    def get_cipher(self) -> Optional[Cipher]:
        return self.cipher

    def set_cipher(self, cipher: Cipher):
        self.cipher = cipher

    def get_iv(self) -> Optional[str]:
        return self.iv

    def set_iv(self, iv: str):
        self.iv = iv

    def get_padder(self) -> Optional[PaddingContext]:
        return self.padder

    def set_padder(self, padder: PaddingContext):
        self.padder = padder

    def get_mac_session_key(self) -> Optional[str]:
        return self.mac_session_key

    def set_mac_session_key(self, mac_key: str):
        self.mac_session_key = mac_key

    def get_interlocutor(self) -> Optional[str]:
        return self.id_of_the_interlocutor

    def set_interlocutor(self, id_of_the_interlocutor: str):
        self.id_of_the_interlocutor = id_of_the_interlocutor