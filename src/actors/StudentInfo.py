class StudentInfo:
    def __init__(self,
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
                 media_voti: float):
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
        self.matricola_casa = matricola_casa
        self.matricola_ospitante = matricola_ospitante
        self.nome = nome
        self.cognome = cognome
        self.email_casa = email_casa
        self.email_ospitante = email_ospitante
        self.data_di_nascita = data_di_nascita
        self.codice_corso_di_laurea = codice_corso_di_laurea
        self.nome_corso_di_laurea = nome_corso_di_laurea
        self.cfu_totali_conseguiti = cfu_totali_conseguiti
        self.media_voti = media_voti

    def introduce(self):
        print(f"Sono {self.nome} {self.cognome}, nato il {self.data_di_nascita}")
        print(f"Email istituzionale: {self.email_casa} | Email ospitante: {self.email_ospitante}")
        print(f"Corso di Laurea: {self.nome_corso_di_laurea} ({self.codice_corso_di_laurea})")
        print(f"CFU: {self.cfu_totali_conseguiti} | Media voti: {self.media_voti}")

    def to_data_list(self):
        return [
            "matricola_casa:" + str(self.matricola_casa),
            "matricola_ospitante:" + str(self.matricola_ospitante),
            "nome:" + str(self.nome),
            "cognome:" + str(self.cognome),
            "email_casa:" + str(self.email_casa),
            "email_ospitante:" + str(self.email_ospitante),
            "data_di_nascita:" + str(self.data_di_nascita),
            "codice_corso_di_laurea:" + str(self.codice_corso_di_laurea),
            "nome_corso_di_laurea:" + str(self.nome_corso_di_laurea),
            "cfu_totali_conseguiti:" + str(self.cfu_totali_conseguiti),
            "media_voti:" + str(self.media_voti)
        ]

