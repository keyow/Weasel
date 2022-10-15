#!/bin/bash
sudo iptables -t nat -D PREROUTING -p tcp -j REDIRECT --to-port 8080
printf "Routing rules flushed\n"