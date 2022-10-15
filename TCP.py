from twisted.internet.protocol import Protocol, ClientFactory, ServerFactory
from twisted.internet import reactor, ssl
from proxy import Proxy
import socket
import struct
import logging
import subprocess

logging.basicConfig(
    format="%(asctime)s %(levelname)s : %(message)s",
    filename="logs/session.log",
    filemode='w',
    level=logging.DEBUG)

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
logging.getLogger().addHandler(console)


class TCP(Protocol):
    SO_ORIGINAL_DST = 80  # for TCP original dst and port

    def write(self, data):
        if data:
            self.transport.write(data)


class TCPProxy(Proxy):
    def __init__(self, bind_port, interface):
        super().__init__(bind_port, interface)
        subprocess.call(['sudo', 'bash', './scripts/rules.sh'])

    def start(self):
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
            for tap in protocol.factory.proxy.taps:
                data = tap.handle(data)
            dataReceived(protocol, data)

        return wrapper

    def __del__(self):
        subprocess.call(['sudo', 'bash', './scripts/reset.sh'])


class TCPServerBridgeProto(TCP):
    def __init__(self):
        self.client = None
        self.ip_tuple = None
        self.buffer = b''

    def connectionMade(self):
        self.ip_tuple = Proxy.socket_tuple(self.transport.socket)
        if self.factory.server_ip == "":
            origin_dst = self.__destinationInfo()
            self.factory.server_ip = origin_dst[0]
            self.factory.server_port = origin_dst[1]
        logging.warning("Client connection successful!")
        logging.debug(f"\n-----------------------------------\n"
                      f"Client:\n |\tIP address: {self.ip_tuple[0][0]}\n |\tPort: {self.ip_tuple[0][1]}\n"
                      f" |\n |\n v\n"
                      f"Proxy (current):\n |\tIP address: {self.ip_tuple[1][0]}\n |\tPort: {self.ip_tuple[1][1]}\n"
                      f" |\n |\n v\n"
                      f"Server (original):\n \tIP address: {self.factory.server_ip}\n \tPort: {self.factory.server_port}\n"
                      f"-----------------------------------")

        self.connectToTargetServer()

    # must be intercepted and modified!
    @TCPProxy.modify
    def dataReceived(self, data):
        logging.info(f"Client > {data}")

        if self.client is not None:
            self.client.write(data)
        else:
            self.buffer += data
            self.connectToTargetServer()

    def __destinationInfo(self):
        dst_info = self.transport.socket.getsockopt(socket.SOL_IP, self.SO_ORIGINAL_DST, 16)
        # ! - big-endian (H - unsigned short, B - unsigned char)
        (proto, port, b1, b2, b3, b4) = struct.unpack('!HHBBBB', dst_info[:8])

        original_dst_ip = '.'.join(map(str, (b1, b2, b3, b4)))
        original_dst_port = port

        return original_dst_ip, original_dst_port

    def connectToTargetServer(self):
        factory = ClientFactory()
        factory.protocol = TCPClientBridgeProto
        factory.proxy = self.factory.proxy
        # for target server current machine IS server:
        factory.server = self
        reactor.connectTCP(self.factory.server_ip, self.factory.server_port, factory)


class TCPClientBridgeProto(TCP):
    def __init__(self):
        self.ip_tuple = None

    def connectionMade(self):
        logging.warning("Target server connection successful.")
        self.ip_tuple = Proxy.socket_tuple(self.transport.socket)
        self.write(self.factory.server.buffer)
        self.factory.server.client = self

    def dataReceived(self, data):
        logging.info(f"Server < {data}")

    def connectionLost(self, reason):
        logging.error(f"[{self.__class__.__name__}] Lose connection...")
        self.factory.server.client = None


class TCPServerFactory(ServerFactory):
    """Custom proxy has to be specified"""

    def __init__(self, server_ip, server_port, protocol, proxy):
        self.server_ip = server_ip
        self.server_port = server_port
        self.proxy = proxy
        self.protocol = protocol
