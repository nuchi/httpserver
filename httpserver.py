#!/usr/bin/env python

import socket
from http_handler import Handler_thread

MAX_CONNECTIONS = 5
Debug = True

# If Debug is True, we'll only allow local connections on port 8000
# Otherwise, we'll accept connections from anywhere on port 80
if Debug:
	hostname = '127.0.0.1'
	PORT = 8000
else:
	hostname = socket.gethostname()
	PORT = 80

# Create new server.
# Following lines adapted from
# https://docs.python.org/2/howto/sockets.html
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((hostname, PORT))
server.listen(MAX_CONNECTIONS)

try:
	while True:
		client_socket, address = server.accept()
		ht = Handler_thread()
		ht.daemon = True
		ht.run(client_socket)
except KeyboardInterrupt:
	server.close()