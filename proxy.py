from abc import abstractmethod


class Proxy:
    def __init__(self,
                 bind_port,
                 server_ip="",
                 server_port=0,
                 interface=""):
        self.bind_port = bind_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.interface = interface
        self.taps = list()

    def add_tap(self, tap):
        self.taps.append(tap)

    @staticmethod
    def socket_tuple(socket):
        return socket.getpeername(), socket.getsockname()

    @abstractmethod
    def start(self):
        pass
