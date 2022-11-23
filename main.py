#!/usr/bin/python3
import argparse

from TCP import *
from taps import *
import sys
import os
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="WeaselUtility",
        description="Weasel is made for processing MITM attacking with certificates exploration and resigning"
    )

    parser.add_argument('-sc', action='store_true')
    options = parser.parse_args()

    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")

    tcp_proxy = TCPProxy(bind_port=8080, interface="192.168.10.128")

    try:
        tcp_proxy.start(options.sc)
    finally:
        subprocess.call(['sudo', 'bash', './scripts/reset.sh'])
