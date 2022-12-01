from OpenSSL import crypto
import random


class CertificateChain:
    """
    CertificateChain class is an abstraction containing certificates list
    Many other certificates processing functions can be added
    That abstraction makes code much easier to understand and read
    """

    def __init__(self, *args):
        self.chain = list()
        for certificate_raw in args:
            self.chain.append([len(certificate_raw), certificate_raw])

    def getList(self):
        """
        Getting list of certificates chain. CA certificate must be the last one

        :return: List object. List contains certificate chain - easy to get certificate by indexes
        """
        return self.chain


def getFields():
    """
    Getting user input for generating CA certificate, certificate request and client certificate

    :return fields: Dictionary object. Contains user input data.
    """
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
    """
    Generate CA certificate using user input parameters
    In WeaselProxy CA certificate is used to sign client certificate

    :param country: String object. Country field
    :param state: String object. State field
    :param locality: String object. Locality field
    :param organization: String object. Organization field
    :param organization_unit: String object. Organization Unit
    :param common_name: String object. Common name
    :param email: String object. Email address
    :param not_before: Unix timestamp. Not before certificate date. May be used to test server on expired certificates
    :param not_after: Unix timestamp. Not after certificate date. May be used to test server on expired certificates
    :return ca_key: CA key
    :return ca_cert: CA certificate
    """
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
    """
    Generates certificate request using user input parameters
    WeaselProxy using request to generate client certificate in a certificate chain

    :param country: String object. Country field
    :param state: String object. State field
    :param locality: String object. Locality field
    :param organization: String object. Organization field
    :param organization_unit: String object. Organization Unit
    :param common_name: String object. Common name
    :param email: String object. Email address
    :return: req: OpenSSL.crypto.X509 object. Certificate request
    """
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
    """
    Generates client certificate using user input parameters
    WeaselProxy using request to generate client certificate in a certificate chain

    :param not_before: Unix timestamp. Not before certificate date. May be used to test server on expired certificates
    :param not_after: Unix timestamp. Not after certificate date. May be used to test server on expired certificates
    :param request: OpenSSL.crypto.X509Req object. Generated certificate request
    :param issuer: OpenSSL.crypto.X509 object. Certificate issuer. In WeaselProxy issuer is CA certificate
    :param issuer_key: OpenSSL.crypto.PKey object. Issuer key. In WeaselProxy issuer key is CA private key (ca_key)
    :return: OpenSSL.crypto.X509 object. Client Certificate
    """
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
