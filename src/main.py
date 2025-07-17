from src.actors.StudentInfo import StudentInfo
from src.certificate_authority.CertificateAuthority import CertificateAuthority
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

student_info = StudentInfo(
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

university_of_origin = University(
    party_id="02",
    nome="Università degli Studi di Salerno",
    nazione="Italia",
    codice_universita="IT-SA01",
    email_contatto="relazioni.internazionali@unisa.it"
)

university_of_origin.add_student_info("01", student_info)

host_university = University(
    party_id="03",
    nome="Università degli Studi di Salerno",
    nazione="Italia",
    codice_universita="IT-SA01",
    email_contatto="relazioni.internazionali@unisa.it"
)

certificate_authority = CertificateAuthority("ca_01")


# --- FASE A1: INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' ---
print("== FASE A == INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' ==\n")

# set-up informazioni per la comunicazione asimmetrica
student.set_up_asymmetric_communication_keys()
student.ask_for_certificate_of_identity(certificate_authority)

university_of_origin.set_up_asymmetric_communication_keys()
university_of_origin.ask_for_certificate_of_identity(certificate_authority)

# scambio certificati di identità
print("=== MESSAGGIO 1 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università")
print("Descrizione  :   Vertificato firmato dalla CA")
print("Contenuto    :   C_Stu = E(PR_{auth}, [T_1 || ID_Stu || PU_Stu])\n")
student_certificate = student.send_certificate_of_identity()
university_of_origin.receive_certificate_of_identity(student_certificate)

print("=== MESSAGGIO 2 ===")
print("Mittente     :   Università")
print("Destinatario :   Studente")
print("Descrizione  :   Certificato firmato dalla CA")
print("Contenuto    :   C_U = E(PR_{auth}, [T_2 || ID_U || PU_U])\n")
university_certificate = university_of_origin.send_certificate_of_identity()
student.receive_certificate_of_identity(university_certificate)

# protocollo di distribuzione sicura della chiave
print("=== MESSAGGIO 3 ===")
print("Mittente     :   Università")
print("Destinatario :   Studente")
print("Descrizione  :   Inizio della challenge - mutual authentication protocol")
print("Contenuto    :   E(PU_Stu, [ID_U || Nonce_1])\n")
first_message = university_of_origin.secure_key_distribution_protocol_send_first_message()

print("=== MESSAGGIO 4 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università")
print("Descrizione  :   Risposta alla challenge e invio sfida di autenticazione all'università")
print("Contenuto    :   E(PU_U, [Nonce_1 || Nonce_2])\n")
second_message = student.secure_key_distribution_protocol_receive_first_message_and_send_second_message(first_message)

print("=== MESSAGGIO 5 ===")
print("Mittente     :   Università")
print("Destinatario :   Studente")
print("Descrizione  :   Conclusione autenticazione reciproca")
print("Contenuto    :   E(PU_Stu, Nonce_2)\n")
third_message = university_of_origin.secure_key_distribution_protocol_receive_second_message_and_send_third_message(second_message)
student.secure_key_distribution_protocol_receive_third_message(third_message)

# scambio della chiave di sessione
print("=== MESSAGGIO 6 ===")
print("Mittente     :   Università")
print("Destinatario :   Studente")
print("Descrizione  :   distribuzione chiave simmetrica")
print("Contenuto    :   E(PU_Stu, E(PR_U, K_S))\n\n")
university_of_origin.set_up_symmetric_communication()
session_info_encrypted = university_of_origin.send_information_symmetric_communication()

session_info_decrypted = student.decrypt_and_verify_message_asymmetric_encryption(session_info_encrypted)
student.set_up_symmetric_communication_from_info_received(session_info_decrypted)

# --- FASE B: RICHIESTA CERTIFICATO ALL'UNIVERSITA' ---
print("== FASE B == RICHIESTA CERTIFICATO ALL'UNIVERSITA' ==\n")

print("=== MESSAGGIO 1 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università")
print("Descrizione  :   Richiesta credenziali\n")
student_certificate_request = student.ask_for_student_info_certificate()

print("=== MESSAGGIO 2 ===")
print("Mittente     :   Università")
print("Destinatario :   Studente")
print("Descrizione  :   Invio credenziali con Merkle Tree per verificarne l'autenticità")
print("Contenuto    :   E(K_S, MerkleTree||E(K_U, RadiceMerkleTree))\n")
encrypted_info = university_of_origin.receive_student_info_certificate_request(student_certificate_request)
student.receive_student_info_certificate(encrypted_info)



university_of_origin.end_symmetric_communication()
student.end_symmetric_communication()

# --- FASE A2: INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' OSPITANTE ---

# set-up informazioni per la comunicazione asimmetrica
host_university.set_up_asymmetric_communication_keys()
host_university.ask_for_certificate_of_identity(certificate_authority)

# scambio certificati di identità
student_certificate = student.send_certificate_of_identity()
host_university.receive_certificate_of_identity(student_certificate)

university_certificate = host_university.send_certificate_of_identity()
student.receive_certificate_of_identity(university_certificate)

# protocollo di distribuzione sicura della chiave
first_message = host_university.secure_key_distribution_protocol_send_first_message()
second_message = student.secure_key_distribution_protocol_receive_first_message_and_send_second_message(first_message)
third_message = host_university.secure_key_distribution_protocol_receive_second_message_and_send_third_message(second_message)
student.secure_key_distribution_protocol_receive_third_message(third_message)

# scambio della chiave di sessione
host_university.set_up_symmetric_communication()
session_info_encrypted = host_university.send_information_symmetric_communication()

session_info_decrypted = student.decrypt_and_verify_message_asymmetric_encryption(session_info_encrypted)
student.set_up_symmetric_communication_from_info_received(session_info_decrypted)


# --- FASE C: INVIO CERTIFICATO ALL'UNIVERSITA' ---
#encrypted_request = host_university.request_info("email_casa")


#student.receive_request_info(encrypted_request)