import subprocess
from TCP import *

tcp_proxy = TCPProxy("192.168.10.131", 8080, bind_port=8081, interface="192.168.10.128")
tcp_proxy.start()
