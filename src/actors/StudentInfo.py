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
            str(self.matricola_casa),
            str(self.matricola_ospitante),
            str(self.nome),
            str(self.cognome),
            str(self.email_casa),
            str(self.email_ospitante),
            str(self.data_di_nascita),
            str(self.codice_corso_di_laurea),
            str(self.nome_corso_di_laurea),
            str(self.cfu_totali_conseguiti),
            str(self.media_voti)
        ]

