from src.actors.CertifiedCommunicatingParty import CertifiedCommunicatingParty
from src.certificate_authority.CertificateAuthority import CertificateAuthority

# set-up di studente, università e certificate authority
student = CertifiedCommunicatingParty(
    party_id="01",
)

university = CertifiedCommunicatingParty(
    party_id="02",
)

certificate_authority = CertificateAuthority("ca_01")

student.set_up_asymmetric_communication_keys()
student.ask_for_certificate_of_identity(certificate_authority)

university.set_up_asymmetric_communication_keys()
university.ask_for_certificate_of_identity(certificate_authority)

#



print(student.certificate_of_identity)

print(university.certificate_of_identity)