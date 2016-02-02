import threading
import socket
import re
import os
import time

status_codes = {200:'OK',
				400:'Bad request',
				404:'Not found',
				405:'Method not allowed', # not currently used!
				408:'Request timeout'}
FIRST_LINE_OK = 0
TIMED_OUT = 1
LINE_TOO_LONG = 2

MAX_WAIT_TIME = 10.0

class HTTP_handler(object):
	def __init__(self, client_socket):
		self.socket = client_socket
	
	def read_first_line(self):
		start_time = time.time()
		# Worst case timing is MAX_WAIT_TIME seconds. It's implemented both through
		# socket timing out, and also manually checking whether we've been looping
		# too long.
		self.socket.settimeout(MAX_WAIT_TIME)
		data = ''
		size_remaining = 1024
		try:
			while data.find('\r\n') == -1:
				elapsed_time = time.time() - start_time
				# Has it been too long since we started?
				if elapsed_time > MAX_WAIT_TIME:
					raise socket.timeout
				self.socket.settimeout(MAX_WAIT_TIME - elapsed_time)
				
				if size_remaining == 0:
					return (LINE_TOO_LONG, '')
				new_data = self.socket.recv(size_remaining)
				size_remaining -= len(new_data)
				data += new_data
		except socket.timeout:
			return (TIMED_OUT, '')
		first_line = data[:data.find('\r\n')]
		return (FIRST_LINE_OK, first_line)
	
	def get_path_from_request(self,first_line):
		"""Returns: is_valid_request, requested_file_path"""
		#Check that the path only uses % and unreserved URI characters
		p = re.compile('^GET (/[\w\-.~%/]*) HTTP/\d\.\d$')
		m = p.match(first_line)
		try:
			path = m.group(1)
			# Okay, it only uses unreserved characters and %. Now decode the path.
			decoded_path = ''
			while path:
				if path[0] != '%':
					decoded_path, path = decoded_path+path[0], path[1:]
				else:
					# trigger exception if % is followed by non-hex, or by fewer than 2 chars
					decoded_path, path = decoded_path+(path[1]+path[2]).decode('hex'), path[3:]
		except:
			return False, ''
		return True, decoded_path
	
	def get_file(self, path):
		"""Returns: is_valid_file, requested_file
		   requested_file is a file object if is_valid_file is True,
		   otherwise requested_file is 'None'. """
		# get rid of ../ trickery
		new_path = 'www'+os.path.normpath(path)
		try:
			f = open(new_path, 'rb')
			return True, f
		except:
			return False, None
	
	def reply_file(self, f):
		"""Sends a 200 OK, and a file object"""
		# Not good for very large files. It reads the whole object
		# before sending it, instead of read-send-read-send.
		content = f.read()
		f.close()
		self.send_reply(200, content)
	
	def reply_invalid_request(self):
		"""Sends a 400 bad request"""
		self.send_reply(400)
	
	def reply_invalid_file(self):
		"""Sends a 404 Not found message"""
		self.send_reply(404)
	
	def reply_invalid_method(self):
		"""Sends a 405 method not allowed"""
		self.send_reply(405)
	
	def reply_timed_out(self):
		"""Sends a 408 client timed out message"""
		self.send_reply(408)
	
	def send_reply(self, status, content=None):
		response = 'HTTP/1.1 {} {}\r\n'.format(status, status_codes[status])
		if not content:
			content = status_codes[status]
		
		response += 'Content-Length: {}\r\n\r\n'.format(len(content))
		response += content
		
		try:
			self.socket.sendall(response)
		except:
			print('An error occurred while sending the reply.')
			pass
		finally:
			self.socket.close()
	
	def handle_request(self):
		"""This is a very permissive server. We'll only inspect
		   the first line of the request, and check if it's something like
		   GET /path/to/file HTTP/1.1 """
		
		status, first_line = self.read_first_line()
		
		if status == TIMED_OUT:
			self.reply_timed_out()
			return
		elif status == LINE_TOO_LONG:
			self.reply_invalid_request()
			return
		# Otherwise status == FIRST_LINE_OK, and we continue
		
		is_valid_request, requested_file_path = self.get_path_from_request(first_line)
		
		if not is_valid_request:
			# Doesn't match GET /(URL-encoded-string) HTTP/#.#
			self.reply_invalid_request()
			return
		
		is_valid_file, requested_file = self.get_file(requested_file_path)
		
		if not is_valid_file:
			# path doesn't resolve to something in the ./www/ directory
			self.reply_invalid_file()
			return
		
		# Everything seems to check out!
		self.reply_file(requested_file)
	

class Handler_thread(threading.Thread):
	def run(self, client_socket):
		new_handler = HTTP_handler(client_socket)
		new_handler.handle_request()