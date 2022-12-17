#!/usr/bin/python3

import os
import argparse
import sys
from WeaselTCP import *
from certgen import *
from OpenSSL import crypto
from time import sleep

if __name__ == "__main__":
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")
    if len(sys.argv) == 1:
        sys.exit("")
    parser = argparse.ArgumentParser(
        prog="WeaselUtility",
        description="Weasel is made for processing MITM attacking with certificates exploration and substitution",
        epilog="Github: https://github.com/keyow/Weasel"
    )
    parser.add_argument('-quiet', action='store_true')
    parser.add_argument('-instant', action='store_true')
    parser.add_argument('-debug', action='store_true')

    subparsers = parser.add_subparsers(dest='mode')

    generate_p = subparsers.add_parser('generate')
    generate_p.add_argument('-sgc', action='store_true')

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
        if options.sgc:
            if not options.quiet:
                ca_cer_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, CA_CERT)
                with open("misc/certinfo/ca_cert.pem", 'wb') as f:
                    f.write(ca_cer_pem)
            client_cer_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, CLIENT_CERT)
            with open("misc/certinfo/client_cert.pem", 'wb') as f:
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

    with open("misc/intro.txt", 'r') as f:
        for line in f.readlines():
            print(line, end='')
            if not options.instant:
                sleep(0.03)
    print('\n' + '\t' * 2 + "Github: https://github.com/keyow/Weasel\n")
    sleep(0.1)
    """
    server_pass = None
    if not options.quiet:
        serve_pass = str(input("Enter server password"))
    """

    weaselProxy = WeaselProxy(bind_port=8080, interface="192.168.10.128", quiet=options.quiet)
    try:
        weaselProxy.start(CertificateChain(client_cer_raw, ca_cer_raw))
    finally:
        subprocess.call(['sudo', 'bash', './scripts/reset.sh'])
