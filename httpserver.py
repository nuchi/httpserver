#!/usr/bin/env python

import socket
from http_handler import Handler_thread

MAX_CONNECTIONS = 5

class HTTPserver(object):
	def __init__(self, localOnly=False, port=80, max_connections=MAX_CONNECTIONS):
		self.port = port
		self.max_connections = max_connections
		if localOnly:
			self.hostname = '127.0.0.1'
		else:
			self.hostname = socket.gethostname()
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	
	def serve(self):
		self.server.bind((self.hostname, self.port))
		self.server.listen(self.max_connections)
		while True:
			client_socket, address = self.server.accept()
			ht = Handler_thread()
			ht.daemon = True
			ht.run(client_socket)
	
	def close(self):
		self.server.close()
	
def create_and_run_server(localOnly=True, port=8000):
	new_server = HTTPserver(localOnly=localOnly, port=port)
	try:
		new_server.serve()
	except KeyboardInterrupt:
		print('\nClosing server.')
		pass
	finally:
		new_server.close()

if __name__ == '__main__':
	create_and_run_server()