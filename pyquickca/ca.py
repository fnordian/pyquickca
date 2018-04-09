import random
from OpenSSL import crypto
from socket import gethostname


def generate_self_signed_ca(ca_cert_file: str, ca_key_file: str):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed ca
    ca = crypto.X509()
    ca.get_subject().C = "DE"
    ca.get_subject().ST = "Duesseldorf"
    ca.get_subject().L = "Duesseldorf"
    ca.get_subject().O = "Dummy GmbH"
    ca.get_subject().OU = "Dummy GmbH"
    ca.get_subject().CN = gethostname()
    ca.set_serial_number(1000)
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(k)

    ca.add_extensions([
        crypto.X509Extension(b"basicConstraints", True,
                             b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True,
                             b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                             subject=ca),
    ])
    ca.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca)
    ])

    ca.sign(k, b'sha1')

    open(ca_cert_file, "wb").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
    open(ca_key_file, "wb").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    return ca, k


def load_cert(ca_cert_file: str, ca_key_file: str):
    with open(ca_cert_file, "rb") as certfile:
        catext = certfile.read()

    with open(ca_key_file, "rb") as keyfile:
        keytext = keyfile.read()

    return (
        crypto.load_certificate(crypto.FILETYPE_PEM, catext),
        crypto.load_privatekey(crypto.FILETYPE_PEM, keytext, None)
    )


def generate_client_cert(ca_cert, ca_key, common_name, client_cert_file, client_key_file):
    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 2048)

    client_cert = crypto.X509()
    client_cert.set_version(2)
    client_cert.set_serial_number(random.randint(50000000, 100000000))

    client_subj = client_cert.get_subject()
    client_subj.commonName = common_name
    # client_subj.organizationName = "user-group"

    client_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
    ])

    client_cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
        crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
        crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
    ])

    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    client_cert.set_subject(client_subj)

    client_cert.set_issuer(ca_cert.get_issuer())
    client_cert.set_pubkey(client_key)
    client_cert.sign(ca_key, b'sha256')

    with open(client_cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert))

    with open(client_key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key))

    return client_cert, client_key


def new_client_cert(common_name, ca_cert_file: str, ca_key_file: str, client_cert_file: str, client_key_file: str):
    try:
        ca_cert, ca_key = load_cert(ca_cert_file, ca_key_file)
    except Exception:
        ca_cert, ca_key = generate_self_signed_ca(ca_cert_file, ca_key_file)

    client_cert, client_key = generate_client_cert(ca_cert, ca_key, common_name, client_cert_file, client_key_file)

    return client_cert, client_key, common_name
