from src.actors.StudentInfo import StudentInfo
from src.certificate_authority.CertificateAuthority import CertificateAuthority
from src.actors.Student import Student
from src.actors.University import University

# --- SET-UP DEGLI ATTORI DEL SISTEMA ---

# Creazione dello studente
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

#Creazione struttura contenente le informazioni dello studente
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

# Creazione Università di origine
university_of_origin = University(
    party_id="02",
    nome="Università degli Studi di Salerno",
    nazione="Italia",
    codice_universita="IT-SA01",
    email_contatto="relazioni.internazionali@unisa.it"
)

# Aggiunta dello studente all'Università di origine
university_of_origin.add_student_info("01", student_info)

# Creazione Università ospitante
host_university = University(
    party_id="03",
    nome="Université de Rene",
    nazione="Francia",
    codice_universita="FR-RE01",
    email_contatto="relations.internationales@unirene.fr"
)

# Creazione CA
certificate_authority = CertificateAuthority("ca_01")


# --- FASE A1: INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' ---
print("== FASE A == INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' DI ORIGINE ==\n")

# Set-up informazioni per la comunicazione asimmetrica
student.set_up_asymmetric_communication_keys()
student.ask_for_certificate_of_identity(certificate_authority)

university_of_origin.set_up_asymmetric_communication_keys()
university_of_origin.ask_for_certificate_of_identity(certificate_authority)

# Scambio certificati di identità,
# lo studente invia il suo certificato firmato dalla CA all’università di origine
print("=== MESSAGGIO 1 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università di origine")
print("Descrizione  :   Vertificato firmato dalla CA")
print("Contenuto    :   C_Stu = E(PR_{auth}, [T_1 || ID_Stu || PU_Stu])\n")
student_certificate = student.send_certificate_of_identity()
university_of_origin.receive_certificate_of_identity(student_certificate)

# L’università di origine invia il suo certificato firmato dalla CA allo studente
print("=== MESSAGGIO 2 ===")
print("Mittente     :   Università di origine")
print("Destinatario :   Studente")
print("Descrizione  :   Certificato firmato dalla CA")
print("Contenuto    :   C_U = E(PR_{auth}, [T_2 || ID_U || PU_U])\n")
university_certificate = university_of_origin.send_certificate_of_identity()
student.receive_certificate_of_identity(university_certificate)

# Protocollo di distribuzione sicura della chiave, inizio challenge,
# l'università invia un nonce1 con la chiave pubblica dello studente
# per sfidarlo a dimostrare di possedere la chiave privata corrispondente
print("=== MESSAGGIO 3 ===")
print("Mittente     :   Università di origine")
print("Destinatario :   Studente")
print("Descrizione  :   Inizio della challenge - mutual authentication protocol")
print("Contenuto    :   E(PU_Stu, [ID_U || Nonce_1])\n")
first_message = university_of_origin.secure_key_distribution_protocol_send_first_message()

# Lo studente invia il nonce1 per dimostrare all'università di essere stato
# in grado di decrittare il messaggio di sfida e ripropone la stessa
# challenge all'università con il nonce2
print("=== MESSAGGIO 4 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università di origine")
print("Descrizione  :   Risposta alla challenge e invio sfida di autenticazione all'università")
print("Contenuto    :   E(PU_U, [Nonce_1 || Nonce_2])\n")
second_message = student.secure_key_distribution_protocol_receive_first_message_and_send_second_message(first_message)

# L'università' invia il nonce2 per dimostrare allo studente di essere stata
# in grado di decrittare il messaggio di sfida
print("=== MESSAGGIO 5 ===")
print("Mittente     :   Università di origine")
print("Destinatario :   Studente")
print("Descrizione  :   Conclusione autenticazione reciproca")
print("Contenuto    :   E(PU_Stu, Nonce_2)\n")
third_message = university_of_origin.secure_key_distribution_protocol_receive_second_message_and_send_third_message(second_message)
student.secure_key_distribution_protocol_receive_third_message(third_message)
#fine challenge

# scambio della chiave di sessione, inizio comunicazione simmetrica
print("=== MESSAGGIO 6 ===")
print("Mittente     :   Università di origine")
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
print("Destinatario :   Università di origine")
print("Descrizione  :   Richiesta credenziali\n")
student_certificate_request = student.ask_for_student_info_certificate()

# L'università invia allo studente le credenziali con il Markle Tree che potrà
# essere usato per verificare l'autenticità dei documenti selezionati e inviati
# a terze perti.
# Questo permette di avere maggiore privacy in quanto lo studente non è cotretto
# a comunicare tutte le informazioni presenti nel Markle Tree ma solo unicamente
# quelle necessarie.
print("=== MESSAGGIO 2 ===")
print("Mittente     :   Università di origine")
print("Destinatario :   Studente")
print("Descrizione  :   Invio credenziali con Merkle Tree per verificarne l'autenticità")
print("Contenuto    :   E(K_S, MerkleTree||E(K_U, RadiceMerkleTree))\n\n")
encrypted_info = university_of_origin.receive_student_info_certificate_request(student_certificate_request)
student.receive_student_info_certificate(encrypted_info)

# Termine comunicazione simmetrica
university_of_origin.end_symmetric_communication()
student.end_symmetric_communication()

# --- FASE A2: INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' OSPITANTE ---
print("== FASE A == INIZIO COMUNICAZIONE STUDENTE - UNIVERSITA' DI ORIGINE ==\n")

# Set-up informazioni per la comunicazione asimmetrica
host_university.set_up_asymmetric_communication_keys()
host_university.ask_for_certificate_of_identity(certificate_authority)

# Scambio certificati di identità,
# lo studente invia il suo certificato firmato dalla CA all’università di origine
print("=== MESSAGGIO 1 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università ospitante")
print("Descrizione  :   Vertificato firmato dalla CA")
print("Contenuto    :   C_Stu = E(PR_{auth}, [T_1 || ID_Stu || PU_Stu])\n")
student_certificate = student.send_certificate_of_identity()
host_university.receive_certificate_of_identity(student_certificate)

# L’università di origine invia il suo certificato firmato dalla CA allo studente
print("=== MESSAGGIO 2 ===")
print("Mittente     :   Università ospitante")
print("Destinatario :   Studente")
print("Descrizione  :   Certificato firmato dalla CA")
print("Contenuto    :   C_U = E(PR_{auth}, [T_2 || ID_U || PU_U])\n")
university_certificate = host_university.send_certificate_of_identity()
student.receive_certificate_of_identity(university_certificate)

# Protocollo di distribuzione sicura della chiave, inizio challenge,
# l'università invia un nonce1 con la chiave pubblica dello studente
# per sfidarlo a dimostrare di possedere la chiave privata corrispondente
print("=== MESSAGGIO 3 ===")
print("Mittente     :   Università ospitante")
print("Destinatario :   Studente")
print("Descrizione  :   Inizio della challenge - mutual authentication protocol")
print("Contenuto    :   E(PU_Stu, [ID_U || Nonce_1])\n")
first_message = host_university.secure_key_distribution_protocol_send_first_message()

# Lo studente invia il nonce1 per dimostrare all'università di essere stato
# in grado di decrittare il messaggio di sfida e ripropone la stessa
# challenge all'università con il nonce2
print("=== MESSAGGIO 4 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università ospitante")
print("Descrizione  :   Risposta alla challenge e invio sfida di autenticazione all'università")
print("Contenuto    :   E(PU_U, [Nonce_1 || Nonce_2])\n")
second_message = student.secure_key_distribution_protocol_receive_first_message_and_send_second_message(first_message)

# L'università' invia il nonce2 per dimostrare allo studente di essere stata
# in grado di decrittare il messaggio di sfida
print("=== MESSAGGIO 5 ===")
print("Mittente     :   Università ospitante")
print("Destinatario :   Studente")
print("Descrizione  :   Conclusione autenticazione reciproca")
print("Contenuto    :   E(PU_Stu, Nonce_2)\n")
third_message = host_university.secure_key_distribution_protocol_receive_second_message_and_send_third_message(second_message)
student.secure_key_distribution_protocol_receive_third_message(third_message)
#fine challenge

# scambio della chiave di sessione, inizio comunicazione simmetrica
print("=== MESSAGGIO 6 ===")
print("Mittente     :   Università ospitante")
print("Destinatario :   Studente")
print("Descrizione  :   distribuzione chiave simmetrica")
print("Contenuto    :   E(PU_Stu, E(PR_U, K_S))\n\n")
host_university.set_up_symmetric_communication()
session_info_encrypted = host_university.send_information_symmetric_communication()

session_info_decrypted = student.decrypt_and_verify_message_asymmetric_encryption(session_info_encrypted)
student.set_up_symmetric_communication_from_info_received(session_info_decrypted)


# --- FASE C e D: INVIO CERTIFICATO ALL'UNIVERSITA' e VERIFICA CERTIFICATO ---
print("== FASE C == INVIO CERTIFICATO ALL'UNIVERSITA' ==\n")

# L'università fa una richiesta di informazioni secifiche allo studente
print("=== MESSAGGIO 1 ===")
print("Mittente     :   Università ospitante")
print("Destinatario :   Studente")
print("Descrizione  :   Richiesta informazioni specifiche")
print("Contenuto    :   E(K_S, Richiesta mail_casa)\n")
encrypted_request = host_university.request_info("email_casa")

# Lo studente invia le informazioni alleganto il Markle Tree e tutti
# i gli Hash dei nodi aggiuntivi necessari per il calcolo dell'autenticità
print("=== MESSAGGIO 2 ===")
print("Mittente     :   Studente")
print("Destinatario :   Università ospitante")
print("Descrizione  :   Informazioni specifiche richiesta con Markle Tree per verificarte l'auteticità")
print("Contenuto    :   E(K_S, foglieRichiesteDelMerkleTree||nodiAggiuntiviDelMerkleTreePerIlCalcoloDellaRadice||E(K_U, RadiceMerkleTree))\n\n")
encrypted_info_student = student.receive_request_info_and_send_info(encrypted_request)

print("== FASE D == VERIFICA CERTIFICATO ==\n")

print("=== MESSAGGIO 1 ===")
print("Mittente     :   Università ospitante")
print("Destinatario :   Studente")
print("Descrizione  :   Notifica di ricezione di certificato corretto o no")
print("Contenuto    :   E(K_S, ack/nack)\n")
# L'università verofica le informazioni e notifica lo studente con un riscontro positivo o negativo
ack_nack = host_university.receive_info_requested(encrypted_info_student, university_of_origin.asymmetric_encryption_information.public_key)

student.receive_feedback_on_info_student(ack_nack)

# Termine della comunicazione cifrata
host_university.end_symmetric_communication()
student.end_symmetric_communication()
