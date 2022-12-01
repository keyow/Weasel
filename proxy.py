from abc import abstractmethod


class Proxy:
    def __init__(self,
                 bind_port,
                 interface=""):
        self.bind_port = bind_port
        self.server_ip = ""
        self.server_port = 0
        self.interface = interface
        self.taps = list()

    @staticmethod
    def socket_tuple(socket):
        return socket.getpeername(), socket.getsockname()

    @abstractmethod
    def start(self, saveCertificate):
        pass
