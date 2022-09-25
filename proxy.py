from abc import abstractmethod


class Proxy:
    def __init__(self,
                 server_ip,
                 server_port,
                 interface,
                 bind_port=0):
        self.server_ip = server_ip
        self.server_port = server_port
        self.bind_port = bind_port
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
