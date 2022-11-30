import sys

from twisted.internet.protocol import Protocol, ClientFactory, ServerFactory
from twisted.internet import reactor
from proxy import Proxy
import socket
import struct
import logging
import subprocess
from abc import abstractmethod
from asn1crypto import x509
from errors import TLS_errors

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
    def substituteCertificate(self, new_certificate_chain):
        pass

    @abstractmethod
    def __splitRecord(self, raw):
        pass

    @staticmethod
    def containsCertificate(raw):
        # Server Hello packet always contains certificate
        # Checking equality of fifth byte and 0x02 (server hello) or 0x0b (which is client certificate by itself)
        return raw[0] == int('16', 16) and (raw[5] == int('02', 16) or raw[5] == int('0b', 16))

    @staticmethod
    def containsError(raw):
        return raw[0] == int('15', 16)

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
        certificateLayer.payload['Certificates'] = list()

        tmp_length = 0
        while tmp_length != certificateLayer.payload['Certificates Length']:
            certificate_length = int.from_bytes(self.raw[12 + offset + tmp_length:15 + offset + tmp_length], 'big')
            certificateLayer.payload['Certificates'].append([certificate_length,
                                                             self.raw[15 + offset + tmp_length:
                                                                      15 + offset + tmp_length +
                                                                      certificate_length]])
            tmp_length += (3 + certificate_length)

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
        for pair in self.certificate.payload["Certificates"]:
            raw += pair[0].to_bytes(3, 'big') + pair[1]

        raw += self.raw[self.certificate.end_index:]

        return raw

    def substituteCertificate(self, new_certificate_chain):
        len_prev = 0
        for pair in self.certificate.payload['Certificates']:
            len_prev += 3
            len_prev += len(pair[1])

        len_cur = 0
        for pair in new_certificate_chain:
            len_cur += 3 + len(pair[1])

        print(f"CURRENT LENGTH: {len_cur}")
        len_adjust = len_cur - len_prev

        self.certificate.payload['Handshake Length'] += len_adjust
        self.certificate.payload['Certificates Length'] += len_adjust
        self.certificate.length += len_adjust
        self.certificate.payload['Certificates'] = new_certificate_chain


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
        for pair in self.certificate.payload["Certificates"]:
            raw += pair[0].to_bytes(3, 'big') + pair[1]

        raw += self.raw[self.certificate.end_index:]

        return raw

    def substituteCertificate(self, new_certificate_chain):
        len_prev = 0
        for pair in self.certificate.payload['Certificates']:
            len_prev += 3
            len_prev += len(pair[1])

        len_cur = 0
        for pair in new_certificate_chain:
            len_cur += 3 + len(pair[1])

        len_adjust = len_cur - len_prev

        self.certificate.payload['Handshake Length'] += len_adjust
        self.certificate.payload['Certificates Length'] += len_adjust
        self.certificate.length += len_adjust
        self.certificate.payload['Certificates'] = new_certificate_chain


class TCP(Protocol):
    SO_ORIGINAL_DST = 80  # for TCP original dst and port
    DataExchangeIndex = 0

    def write(self, data):
        if data:
            self.transport.write(data)


class WeaselProxy(Proxy):
    def __init__(self, bind_port, interface):
        super().__init__(bind_port, interface)
        self.fakeCertificatesChain = None
        subprocess.call(['sudo', 'bash', './scripts/rules.sh'])

    def start(self, fakeCertificateChain):
        logging.info("tcp_proxy: ON")
        logging.debug(f"interface: {(lambda arg: arg if arg is not None else 'None')(self.interface)}")
        logging.debug(f"bind_port: {self.bind_port}")

        # ready to redirect packets to server_ip on server_port -> using factory below to produce protocol
        factory = TCPServerFactory(self.server_ip, self.server_port, protocol=TCPServerBridgeProto, proxy=self)

        # listening traffic on bind port
        listener = reactor.listenTCP(self.bind_port, factory, interface=self.interface)

        self.fakeCertificatesChain = fakeCertificateChain
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
    @WeaselProxy.modify
    def dataReceived(self, data):
        if TLS_Packet.containsCertificate(data):
            logging.critical(f"Got client certificate")
            packet = TLS_ClientCertificatePacket(data)  # test for server hello
            packet.substituteCertificate(self.factory.proxy.fakeCertificatesChain.getList())
            data = packet.dump()

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
        if TLS_Packet.containsCertificate(data):
            logging.critical(f"Got server certificate")

            packet = TLS_ServerHelloPacket(data)  # test for server hello
            cert = x509.Certificate.load(packet.certificate.payload['Certificates'][0][1])

            # do something with cert here
            packet.certificate.payload['Certificates'][0][1] = cert.dump()
        elif TLS_Packet.containsError(data):
            logging.warning("Got error from server. Take a look!")
            logging.warning(f"Error text: {TLS_errors[data[6]]}")

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
