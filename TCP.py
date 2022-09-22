from twisted.internet.protocol import Protocol, ClientFactory, ServerFactory
from twisted.internet import reactor
from proxy import Proxy


class TCP(Protocol):
    def dataReceived(self, data):
        print(data)

    def write(self, data):
        if data:
            self.transport.write(data)


class TCPServerBridgeProto(TCP):
    def __init__(self):
        self.client = None

    def connectionMade(self):
        self.transport.setTcpNoDelay(True)
        self.ip_tuple = Proxy.socket_tuple(self.transport.socket)

        print(f"Client connection successful\n"
              f"-----------------------------------\n"
              f"Client:\n\tIP address: {self.ip_tuple[0][0]}\n\tPort: {self.ip_tuple[0][1]}\n"
              f"Server (current):\n\tIP address: {self.ip_tuple[1][0]}\n\tPort: {self.ip_tuple[1][1]}\n"
              f"-----------------------------------\n")

        # factory produces TCP proto for Client<->Server
        #factory = ClientFactory()
        #factory.protocol = TCPClientBridgeProto
        #factory.proxy = self.factory.proxy  # copying proxy for client connection
        #factory.server = self

        # reactor.connectTCP instance: host + port + factory (Client factory)
        # Connecting a TCP client
        #reactor.connectTCP(self.factory.server_ip, self.factory.server_port, factory)
        #print("\tTransparent proxy client connection: ON")
        #print("\t", self.factory.server_ip, self.factory.server_port, factory)

    # must be intercepted!
    def dataReceived(self, data):
        print(f"[CLIENT_DEBUG]: {data}")
        if self.client is not None:
            data = b'strange....'
            self.client.write(data)
            print("From client: ", self.client)

"""
class TCPClientBridgeProto(TCP):
    def __init__(self):
        self.client = None
        self.ip_tuple = None
        self.connection_status = False

    # low latency idea?
    def connectionMade(self):
        self.transport.setTcpNoDelay(True)
        if self.connection_status is None:
            self.connection_status = True
        self.ip_tuple = Proxy.socket_tuple(self.transport.socket)
        self.factory.server.client = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = b''

    def dataReceived(self, data):
        print(f"[SERVER_DEBUG]: {data}")

    def connectionLost(self, reason):
        print(f"[{self.__class__.__name__}] Lose connection...")
"""


class TCPServerFactory(ServerFactory):
    """Custom proxy has to be specified"""
    def __init__(self, server_ip, server_port, protocol, proxy):
        self.server_ip = server_ip
        self.server_port = server_port
        self.proxy = proxy
        self.protocol = protocol


class TCPProxy(Proxy):
    def start(self):
        print("[DEBUG] tcp_proxy: ON")
        print(f"\tinterface: {self.interface}")
        print(f"\tbind_port: {self.bind_port}")
        # ready to redirect packets to server_ip on server_port -> using factory below to produce protocol
        factory = TCPServerFactory(self.server_ip, self.server_port, protocol=TCPServerBridgeProto, proxy=self)

        # listening traffic on bind port
        listener = reactor.listenTCP(self.bind_port, factory, interface=self.interface)

        reactor.run()
