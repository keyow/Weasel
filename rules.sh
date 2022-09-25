#!/bin/bash
printf "Routing is set. Current routing rules:\n\n"
sudo iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 8080
sudo iptables -t nat -L
printf "\n"