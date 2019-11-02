from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from gen_key import gen_keys
import datetime


def create_certificate(password, private_key_file, public_key_file, user_name, certificate_file):
    private_key, public_key = gen_keys(password, private_key_file, public_key_file)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                                  x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
                                  x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
                                  x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
                                  x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Dept"),
                                  x509.NameAttribute(NameOID.COMMON_NAME, user_name), ])

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)

    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(1))
    builder = builder.not_valid_after(datetime.datetime(2020, 8, 2))

    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.public_key(public_key)

    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,)

    certificate = builder.sign(private_key=private_key,
                               algorithm=hashes.SHA256(),
                               backend=default_backend())

    cert_name = certificate_file
    with open(cert_name, 'wb') as file:
        file.write(certificate.public_bytes(serialization.Encoding.PEM))


create_certificate("user 1 password", "kr_user1.pem", "ku_user1.pem", u"User 1", "user1_cert.pem")
create_certificate("user 2 secret", "kr_user2.pem", "ku_user2.pem", u"User 2", "user2_cert.pem")

