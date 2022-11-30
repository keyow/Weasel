from OpenSSL import crypto
import random


class CertificateChain:
    def __init__(self, *args):
        self.chain = list()
        for certificate_raw in args:
            self.chain.append([len(certificate_raw), certificate_raw])

    def getList(self):
        return self.chain


def getFields():
    fields = dict()

    fields["C"] = input("Country: ")
    fields["S"] = input("State: ")
    fields["L"] = input("Locality: ")
    fields["O"] = input("Organization: ")
    fields["OU"] = input("Organization Unit: ")
    fields["CN"] = input("Common name: ")
    fields["emailAddress"] = input("Email address: ")
    fields["notBefore"] = input("Not before: ")
    fields["notAfter"] = input("Not after: ")

    return fields


def generateCA(country, state, locality, organization, organization_unit, common_name, email, not_before, not_after):
    serial_number = random.getrandbits(64)
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_serial_number(serial_number)
    ca_cert.get_subject().C = country
    ca_cert.get_subject().ST = state
    ca_cert.get_subject().L = locality
    ca_cert.get_subject().O = organization
    ca_cert.get_subject().OU = organization_unit
    ca_cert.get_subject().CN = common_name
    ca_cert.get_subject().emailAddress = email
    ca_cert.gmtime_adj_notBefore(int(not_before))
    ca_cert.gmtime_adj_notAfter(int(not_after))
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key)
    ca_cert.sign(ca_key, 'sha256')

    return ca_key, ca_cert


def generateRequest(country, state, locality, organization, organization_unit, common_name, email):
    req_key = crypto.PKey()
    req_key.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    req.get_subject().C = country
    req.get_subject().ST = state
    req.get_subject().L = locality
    req.get_subject().O = organization
    req.get_subject().OU = organization_unit
    req.get_subject().CN = common_name
    req.get_subject().emailAddress = email
    req.set_pubkey(req_key)
    req.sign(req_key, 'sha256')

    return req


def generateCertificate(not_before, not_after, request, issuer, issuer_key):
    serial_number = random.getrandbits(64)
    new_cert = crypto.X509()
    new_cert.set_serial_number(serial_number)
    new_cert.gmtime_adj_notBefore(int(not_before))
    new_cert.gmtime_adj_notAfter(int(not_after))
    new_cert.set_subject(request.get_subject())
    new_cert.set_issuer(issuer.get_subject())
    new_cert.set_pubkey(request.get_pubkey())
    new_cert.sign(issuer_key, 'sha256')

    return new_cert
