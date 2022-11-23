from abc import abstractmethod


class Tap:
    def __init__(self, name):
        self.name = name

    @abstractmethod
    def handle(self, data):
        pass


class ChangeLastByte(Tap):
    def handle(self, data):
        ba_data = bytearray(data)
        ba_data[-1] = 0
        data = bytes(ba_data)
        return data


class ChangeCertificateDate(Tap):
    def handle(self, certificate):
        print("Handler: ")
        print(certificate.native)
        print(f"DUMP\n{certificate.dump()}")
        return certificate.dump()