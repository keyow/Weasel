from abc import abstractmethod


class Tap:
    def __init__(self, name):
        self.name = name

    @abstractmethod
    def handle(self, data):
        pass
