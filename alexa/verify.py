#!/usr/bin/python

import socket
import sys

with open('./AlexaTopCA_debug.txt') as f:
    lines = f.readlines()

for i in range(0, len(lines)):
    lines[i] = lines[i][0:-1]

x = 0
for i in lines:
	try:
		result = socket.gethostbyname(lines[x])
		print("{}: {}").format(i, result)
		x += 1
	except socket.error as e:
		print e
		x += 1
