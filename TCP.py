from twisted.internet.protocol import Protocol, ClientFactory, ServerFactory
from twisted.internet import reactor
from proxy import Proxy
import socket
import struct
import logging
import subprocess
from abc import abstractmethod
from asn1crypto import x509
from pprint import pprint
import json
from OpenSSL import crypto
from random import random

logging.basicConfig(
    format="%(asctime)s %(levelname)s : %(message)s",
    filename="logs/session.log",
    filemode='w',
    level=logging.DEBUG)

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
logging.getLogger().addHandler(console)


class TLS_RecordLayer:
    def __init__(self):
        self.start_index = 0
        self.end_index = 0
        self.content_type = None
        self.version = None
        self.length = None
        self.payload = dict()

    def getHeader(self):
        return self.content_type, self.version, self.length


class TLS_Packet:
    def __init__(self, packet_bytes=None):
        self.raw = packet_bytes

    def load(self, raw):
        self.raw = raw
        self.__splitRecord(raw)

    @abstractmethod
    def dump(self):
        pass

    @abstractmethod
    def __splitRecord(self, raw):
        pass

    @staticmethod
    def containsCertificate(raw, src):
        # Server Hello packet always contains certificate
        # Checking equality of fifth byte and 0x02 (server hello) or 0x1b (which is client certificate by itself)
        return raw[5] == int('02', 16) or raw[5] == int('0b', 16)

    def _parseCertificates(self, offset):
        if self.raw is None:
            return
        certificateLayer = TLS_RecordLayer()

        certificateLayer.content_type = self.raw[offset]
        certificateLayer.version = self.raw[1 + offset:3 + offset]
        certificateLayer.length = int.from_bytes(self.raw[3 + offset:5 + offset], 'big')
        certificateLayer.payload['Handshake Type'] = self.raw[5 + offset]
        certificateLayer.payload['Handshake Length'] = int.from_bytes(self.raw[6 + offset:9 + offset], 'big')
        certificateLayer.payload['Certificates Length'] = int.from_bytes(self.raw[9 + offset:12 + offset], 'big')
        certificateLayer.payload['Certificates'] = dict()

        tmp_length = 0
        certificateIndex = 0
        while tmp_length != certificateLayer.payload['Certificates Length']:
            certificate_length = int.from_bytes(self.raw[12 + offset + tmp_length:15 + offset + tmp_length], 'big')
            certificateLayer.payload['Certificates'][certificateIndex] = [certificate_length,
                                                                          self.raw[15 + offset + tmp_length:
                                                                                   15 + offset + tmp_length +
                                                                                   certificate_length]]
            tmp_length += (3 + certificate_length)
            certificateIndex += 1

        return certificateLayer


class TLS_ServerHelloPacket(TLS_Packet):
    def __init__(self, packet_bytes=None):
        super().__init__(packet_bytes)
        self.server_hello = TLS_RecordLayer()  # empty (no need to use)
        self.certificate = TLS_RecordLayer()
        self.server_key_exchange = TLS_RecordLayer()  # empty (no need to use)
        self.server_hello_done = TLS_RecordLayer()  # empty (no need to use)

        if packet_bytes is not None:
            self.__splitRecord(self.raw)

    def __splitRecord(self, raw):
        # parsing certificate only (just in this case --- many new cases can be added soon)
        offset = 5 + int.from_bytes(raw[3:5], 'big')

        self.certificate = self._parseCertificates(offset)
        self.certificate.start_index = offset
        self.certificate.end_index = offset + 1 + 2 + 2 + self.certificate.length

    def dump(self):
        raw = b''

        raw += self.raw[:self.certificate.start_index]

        raw += self.certificate.content_type.to_bytes(1, 'big')
        raw += self.certificate.version
        raw += self.certificate.length.to_bytes(2, 'big')

        raw += self.certificate.payload["Handshake Type"].to_bytes(1, 'big')
        raw += self.certificate.payload["Handshake Length"].to_bytes(3, 'big')
        raw += self.certificate.payload["Certificates Length"].to_bytes(3, 'big')
        for pair in self.certificate.payload["Certificates"].values():
            raw += pair[0].to_bytes(3, 'big') + pair[1]

        raw += self.raw[self.certificate.end_index:]

        return raw


class TLS_ClientCertificatePacket(TLS_Packet):
    def __init__(self, packet_bytes=None):
        super().__init__(packet_bytes)
        self.certificate = TLS_RecordLayer()
        self.client_key_exchange = TLS_RecordLayer()  # empty (no need to use)
        self.certificate_verify = TLS_RecordLayer()  # empty (no need to use)
        self.change_cipher_spec = TLS_RecordLayer()  # empty (no need to use)
        self.encrypted_handshake_message = TLS_RecordLayer()  # empty (no need to use)

        if packet_bytes is not None:
            self.__splitRecord(self.raw)

    def __splitRecord(self, raw):
        offset = 0
        self.certificate = self._parseCertificates(offset)
        self.certificate.start_index = offset
        self.certificate.end_index = offset + 1 + 2 + 2 + self.certificate.length

    def dump(self):
        raw = b''
        raw += self.raw[:self.certificate.start_index]

        raw += self.certificate.content_type.to_bytes(1, 'big')
        raw += self.certificate.version
        raw += self.certificate.length.to_bytes(2, 'big')

        raw += self.certificate.payload["Handshake Type"].to_bytes(1, 'big')
        raw += self.certificate.payload["Handshake Length"].to_bytes(3, 'big')
        raw += self.certificate.payload["Certificates Length"].to_bytes(3, 'big')
        for pair in self.certificate.payload["Certificates"].values():
            raw += pair[0].to_bytes(3, 'big') + pair[1]

        raw += self.raw[self.certificate.end_index:]

        return raw


class TCP(Protocol):
    SO_ORIGINAL_DST = 80  # for TCP original dst and port
    DataExchangeIndex = 0

    def write(self, data):
        if data:
            self.transport.write(data)


class TCPProxy(Proxy):
    saveCertificates = None

    def __init__(self, bind_port, interface):
        super().__init__(bind_port, interface)
        subprocess.call(['sudo', 'bash', './scripts/rules.sh'])

    def start(self, saveCertificates):
        TCPProxy.saveCertificates = saveCertificates
        logging.info("tcp_proxy: ON")
        logging.debug(f"interface: {(lambda arg: arg if arg is not None else 'None')(self.interface)}")
        logging.debug(f"bind_port: {self.bind_port}")

        # ready to redirect packets to server_ip on server_port -> using factory below to produce protocol
        factory = TCPServerFactory(self.server_ip, self.server_port, protocol=TCPServerBridgeProto, proxy=self)

        # listening traffic on bind port
        listener = reactor.listenTCP(self.bind_port, factory, interface=self.interface)

        reactor.run()

    @staticmethod
    def modify(dataReceived):
        def wrapper(protocol, data):
            return dataReceived(protocol, data)

        return wrapper


class TCPServerBridgeProto(TCP):
    def __init__(self):
        self.target_bridge = None
        self.ip_tuple = None
        self.buffer = b''

    def connectionMade(self):
        self.ip_tuple = Proxy.socket_tuple(self.transport.socket)
        if self.factory.server_ip == "":
            origin_dst = self.__destinationInfo()
            self.factory.server_ip = origin_dst[0]
            self.factory.server_port = origin_dst[1]
        logging.info("Client connection successful!")
        print(TCPProxy.saveCertificates)
        logging.debug(f"\n-----------------------------------\n"
                      f"Client:\n |\tIP address: {self.ip_tuple[0][0]}\n |\tPort: {self.ip_tuple[0][1]}\n"
                      f" |\n |\n v\n"
                      f"Proxy (current):\n |\tIP address: {self.ip_tuple[1][0]}\n |\tPort: {self.ip_tuple[1][1]}\n"
                      f" |\n |\n v\n"
                      f"Server (original):\n \tIP address: {self.factory.server_ip}\n \tPort: {self.factory.server_port}\n"
                      f"-----------------------------------")

        '''
        first option is to connect to server when client is connected to proxy (immediately)
        after we connect to server, we get self.client initialized
        current machine acts as a CLIENT for target server
        that's why we use self.client.write(data) (we send data to server)
        '''
        self.connectToTargetServer()

    # must be intercepted and modified!
    @TCPProxy.modify
    def dataReceived(self, data):
        if TLS_Packet.containsCertificate(data, src='client'):
            logging.critical(f"Got client certificate:")
            print("CLIENT DATA")
            print(data)
            packet = TLS_ClientCertificatePacket(data)  # test for server hello
            certificates_count = len(packet.certificate.payload['Certificates'])
            head_cert = x509.Certificate.load(
                packet.certificate.payload['Certificates'][1 if certificates_count >= 1 else 0][1])

            # Creating CA certificate
            serialnumber = random.getrandbits(64)
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)
            ca_cert = crypto.X509()
            ca_cert.get_subject().C = "RU"
            ca_cert.get_subject().ST = "Moscow District"
            ca_cert.get_subject().L = "Moscow"
            ca_cert.get_subject().O = "IU8 was here"
            ca_cert.get_subject().CN = "Kirill was in this CA"
            ca_cert.get_subject().emailAddress = "CA@gmail.com"
            ca_cert.set_serial_number(serialnumber)
            ca_cert.gmtime_adj_notBefore(0)
            ca_cert.gmtime_adj_notAfter(315360000)
            ca_cert.set_issuer(ca_cert.get_subject())
            ca_cert.set_pubkey(k)
            ca_cert.sign(k, 'sha512')
            ca_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
            ca_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)
            req = crypto.X509Req()
            req.get_subject().C = "RU"
            req.get_subject().ST = "Moscow District"
            req.get_subject().L = "Moscow"
            req.get_subject().O = "IU8 was here"
            req.get_subject().CN = "Kirill was here"
            req.get_subject().emailAddress = "fsdjgjspfpjs@gmail.com"
            req.set_pubkey(key)
            req.sign(key, 'sha512')
            csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

            serialnumber = random.getrandbits(64)
            new_cert = crypto.X509()
            new_cert.set_serial_number(serialnumber)
            new_cert.gmtime_adj_notAfter(0)
            new_cert.gmtime_adj_notAfter(31536000)
            new_cert.set_subject(req.get_subject())
            new_cert.set_issuer(ca_cert.get_subject())
            new_cert.set_pubkey(key)
            

            print("\nCSR FOR NEW CERTIFICATE:")
            print(csr.decode(encoding='utf-8'))

            print("CLIENT CERT NATIVE")
            pprint(head_cert.native)
            # do something with cert here

            serialnumber = random.getrandbits(64)
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, packet.certificate.payload['Certificates'][
                1 if certificates_count >= 1 else 0][1])

            packet.certificate.payload['Certificates'][0][1] = head_cert.dump()
            print("CLIENT DUMP:")
            print(packet.dump())
            if TCPProxy.saveCertificates:
                with open("misc/certinfo/client_cert.txt", 'w') as f:
                    json.dump(head_cert.native, f, default=str)

        if self.target_bridge is not None:
            self.__transferToClientBridge(data)

        self.buffer += data
        # second option: initial client is none, so we connect to server after we receive data > client is not none
        # self.connectToTargetServer()
        self.DataExchangeIndex += 1

    def connectToTargetServer(self):
        factory = ClientFactory()
        factory.protocol = TCPClientBridgeProto
        factory.proxy = self.factory.proxy
        # for target client current machine IS server (used for responding to client):
        factory.server = self
        reactor.connectTCP(self.factory.server_ip, self.factory.server_port, factory)

    def __destinationInfo(self):
        dst_info = self.transport.socket.getsockopt(socket.SOL_IP, self.SO_ORIGINAL_DST, 16)
        # ! - big-endian (H - unsigned short, B - unsigned char)
        (proto, port, b1, b2, b3, b4) = struct.unpack('!HHBBBB', dst_info[:8])

        original_dst_ip = '.'.join(map(str, (b1, b2, b3, b4)))
        original_dst_port = port

        return original_dst_ip, original_dst_port

    def __transferToClientBridge(self, data):
        print("Writing to connected server")
        self.target_bridge.write(data)


class TCPClientBridgeProto(TCP):
    def __init__(self):
        self.ip_tuple = None

    def connectionMade(self):
        logging.info('Server connection successful!')
        self.ip_tuple = Proxy.socket_tuple(self.transport.socket)

        # if buffer is not empty means that connection hasn't been terminated and every packet was sent at once
        if self.factory.server.buffer != b'':
            print("CLIENT BUFFER IS NOT EMPTY -> WRITING TO SERVER")
            self.write(self.factory.server.buffer)
            self.factory.server.buffer = b''

        self.factory.server.target_bridge = self

    def dataReceived(self, data):
        if TLS_Packet.containsCertificate(data, src='server'):
            logging.critical(f"Got client certificate:")
            print("SERVER INITIAL DATA")
            print(data)
            packet = TLS_ServerHelloPacket(data)  # test for server hello
            cert = x509.Certificate.load(packet.certificate.payload['Certificates'][0][1])

            native_cert = cert.native
            # new_not_before = datetime(2020, 11, 16, 0, 0, 0, tzinfo=timezone.utc)
            print("CURRENT VALID_BEFORE DATETIME")

            """
            valid_before_idx = data.find(b'\x17\x0d') + 2
            temp = bytearray(data)
            temp[valid_before_idx + 1] -= 1
            
            print(temp)
            for byte in temp[valid_before_idx:valid_before_idx + 13]:
                print(chr(byte))

            print(str(len(data)) + " --- " + str(len(bytes(temp))))
            data = bytes(temp)
            
            ba_data = bytearray(data)
            ba_data[valid_before_idx + 1] = 48
            data = bytes(ba_data)
            print(data[valid_before_idx:valid_before_idx + 13])
            """
            print("SERVER NATIVE CERT:")
            pprint(native_cert)

            # do something with cert here
            packet.certificate.payload['Certificates'][0][1] = cert.dump()
            print("SERVER DUMP:")
            print(packet.dump())
            if TCPProxy.saveCertificates:
                with open("misc/certinfo/server_cert.txt", 'w') as f:
                    json.dump(cert.native, f, default=str)

        # TODO: expand TLS class for different records, check if that record is server hello (make nested TLS records)
        # target server response (transfer from proxy to client)
        self.factory.server.transport.write(data)
        self.DataExchangeIndex += 1

    def connectionLost(self, reason):
        logging.error(f"[{self.__class__.__name__}] Lose connection...")


class TCPServerFactory(ServerFactory):
    """Custom proxy has to be specified"""

    def __init__(self, server_ip, server_port, protocol, proxy):
        self.server_ip = server_ip
        self.server_port = server_port
        self.proxy = proxy
        self.protocol = protocol
