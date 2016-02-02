#!/usr/bin/env python

import unittest
import httpserver
import requests
import threading
import socket
import time

base_url = 'http://127.0.0.1:8000'

class TestServerResponses(unittest.TestCase):
	def test_ok_file(self):
		response = requests.get(base_url+'/test.txt')
		self.assertEqual(response.status_code, 200)
	
	def test_request_too_long(self):
		response = requests.get(base_url+'/'+'a'*1024)
		self.assertEqual(response.status_code, 400)
	
	def test_file_not_found(self):
		response = requests.get(base_url+'/no_such_file.txt')
		self.assertEqual(response.status_code, 404)
	
	@unittest.skip('405 status code not implemented yet')
	def test_method_not_allowed(self):
		response = requests.post(base_url+'/')
		self.assertEqual(response.status_code, 405)
	
	def test_timeout(self):
		timing_out_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		timing_out_socket.connect(('127.0.0.1', 8000))
		timing_out_socket.sendall('GET /hanging...')
		time.sleep(11.0)
		response = timing_out_socket.recv(1024)
		timing_out_socket.close()
		self.assertEqual(response[:13], 'HTTP/1.1 408 ')
	
	def test_path_safety(self):
		paths_and_responses = {'/test.txt':200,
								'/extra/test2.txt':200,
								'/extra/../test.txt':200,
								'/../../../../../../../../etc/passwd':404}
		for path in paths_and_responses:
			response = requests.get(base_url+path)
			self.assertEqual(response.status_code, paths_and_responses[path])
		
		bad_request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		bad_request_socket.connect(('127.0.0.1', 8000))
		# Path should start with '/'
		bad_request_socket.sendall('GET ../../../../../../../../etc/passwd HTTP/1.1\r\n\r\n')
		f = bad_request_socket.makefile()
		response = f.readline()
		f.close()
		self.assertEqual(response[:13], 'HTTP/1.1 400 ')

if __name__ == '__main__':
	server_thread = threading.Thread(target=httpserver.create_and_run_server)
	server_thread.daemon = True
	server_thread.start()
	print('Opened server.')
	time.sleep(1.0)
	unittest.main(verbosity=2)