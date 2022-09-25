#!/usr/bin/python3

from TCP import *
from taps import *
import subprocess
import sys
import os

if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")

subprocess.call(['sudo', 'bash', './rules.sh'])
tcp_proxy = TCPProxy("192.168.10.131", 8080, bind_port=8080, interface="192.168.10.128")

tcp_proxy.add_tap(ChangeLastByte("change_last_byte"))
tcp_proxy.start()
