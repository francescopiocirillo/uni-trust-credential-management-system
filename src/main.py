from src.actors.CertifiedCommunicatingParty import CertifiedCommunicatingParty
from src.certificate_authority.CertificateAuthority import CertificateAuthority
from src.utils.CryptoUtils import CryptoUtils
from src.actors.Student import Student
from src.actors.University import University

# --- SET-UP DI STUDENTE, UNIVERSITA' E CERTIFICATE AUTHORITY
student = Student(
    party_id="01",
    matricola_casa="0123456789",
    matricola_ospitante="0123456789",
    nome="Mario",
    cognome="Rossi",
    email_casa="mario.rossi@studenti.casa.it",
    email_ospitante="mario.rossi@etudiant.maison.fr",
    data_di_nascita="01/01/2000",
    codice_corso_di_laurea="LM-32",
    nome_corso_di_laurea="Magistrale in Ingegneria Informatica",
    cfu_totali_conseguiti=100,
    media_voti=28.0
)

university_of_origin = CertifiedCommunicatingParty(
    party_id="02",
    nome="Università degli Studi di Salerno",
    nazione="Italia",
    codice_universita="IT-SA01",
    email_contatto="relazioni.internazionali@unisa.it"
)

certificate_authority = CertificateAuthority("ca_01")


# --- FASE A: INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' ---

# set-up informazioni per la comunicazione asimmetrica
student.set_up_asymmetric_communication_keys()
student.ask_for_certificate_of_identity(certificate_authority)

university_of_origin.set_up_asymmetric_communication_keys()
university_of_origin.ask_for_certificate_of_identity(certificate_authority)

# scambio certificati di identità
student_certificate = student.send_certificate_of_identity()
university_of_origin.receive_certificate_of_identity(student_certificate)

university_certificate = university_of_origin.send_certificate_of_identity()
student.receive_certificate_of_identity(university_certificate)

# protocollo di distribuzione sicura della chiave
first_message = university_of_origin.secure_key_distribution_protocol_send_first_message()
second_message = student.secure_key_distribution_protocol_receive_first_message_and_send_second_message(first_message)
third_message = university_of_origin.secure_key_distribution_protocol_receive_second_message_and_send_third_message(second_message)
student.secure_key_distribution_protocol_receive_third_message(third_message)

# scambio della chiave di sessione
university_of_origin.set_up_symmetric_communication()
session_info_encrypted = university_of_origin.send_information_symmetric_communication()

session_info_decrypted = student.decrypt_message_asymmetric_encryption(session_info_encrypted)
student.set_up_symmetric_communication_from_info_received(session_info_decrypted)

#

