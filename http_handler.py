import threading
import socket
import re
import os
import time
import subprocess

status_codes = {200:'OK',
				400:'Bad request',
				404:'Not found',
				405:'Method not allowed', # not currently used!
				408:'Request timeout'}
FIRST_LINE_OK = 0
TIMED_OUT = 1
LINE_TOO_LONG = 2

MAX_WAIT_TIME = 10.0

class BadRequestException(Exception):
	pass

def socket_lines(sock, wait_time=MAX_WAIT_TIME):
	""" Adapted from Aaron Watters at stackoverflow """
	buff = ''
	buffering = True
	start_time = time.time()
	while buffering or buff:
		if buffering:
			elapsed_time = time.time() - start_time
			if elapsed_time > wait_time:
				raise socket.timeout
			sock.settimeout(wait_time - elapsed_time)
			new_input = sock.recv(4096)
			
			if new_input:
				buff += new_input
			else:
				buffering = False
		
		if '\r\n' in buff:
			line, buff = buff.split('\r\n', 1)
			yield line+'\r\n'
		elif not buffering:
			yield buff
	


class HTTP_Responder(object):
	def __init__(self, client_socket):
		self.socket = client_socket
	
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
	
	def reply_file(self, f):
		"""Sends a 200 OK, and a file object"""
		# Not good for very large files. It reads the whole object
		# before sending it, instead of read-send-read-send.
		content = f.read()
		f.close()
		# lookup file extension
		extention = f.name.split('.')[-1] # file extension
		extensions = {'jpg':'image/jpeg', 'txt':'text/plain'}
		contentType = extensions.get(extention, None)
		self.send_reply(200, content, contentType=contentType)
	
	def send_reply(self, status, content=None, contentType=None):
		response = 'HTTP/1.1 {} {}\r\n'.format(status, status_codes[status])
		if not content:
			content = status_codes[status]
		
		if contentType:
			response += 'Content-Type: {}\r\n'.format(contentType)
		response += 'Content-Length: {}\r\n\r\n'.format(len(content))
		
		response += content
		
		try:
			self.socket.sendall(response)
		except:
			print('An error occurred while sending the reply.')
			pass
		finally:
			self.socket.close()
	


class Base_Request_handler(object):
	def __init__(self, method, path, headers, body, sock):
		self.method = method
		self.path = path
		self.headers = headers
		self.body = body
		#self.contents_generator = contents_generator
		self.socket = sock
	


class Static_handler(Base_Request_handler):
	def handle_request(self):
		responder = HTTP_Responder(self.socket)
		path = 'www'+self.path
		
		if self.method != 'GET':
			responder.reply_invalid_method()
			return
		
		try:
			f = open(path)
		except IOError:
			responder.reply_invalid_file()
			return
		
		responder.reply_file(f)
	


class CGI_handler(Base_Request_handler):
	def handle_request(self):
		responder = HTTP_Responder(self.socket)
		path = self.path[1:]
		
		if not os.path.isfile(path):
			responder.reply_invalid_file()
			return
		
		



class HTTP_handler(object):
	def __init__(self, client_socket):
		self.socket = client_socket
	
	def read_and_parse_request(self, wait_time=MAX_WAIT_TIME):
		start_time = time.time()
		request = ''
		buffering = True
		while buffering:
			elapsed_time = time.time() - start_time
			if elapsed_time > wait_time:
				raise socket.timeout
			self.socket.settimeout(wait_time - elapsed_time)
			new_input = self.socket.recv(4096)
			
			if not new_input:
				buffering = False
			
			request += new_input
			
			# Check if we're done
			if '\r\n\r\n' in request:
				status_line, headers, body = self.parse_request(request)
				temp_headers = map(lambda x: x.split(':',1), headers)
				temp_headers = map(lambda y: (y[0].lower(), y[1]), temp_headers)
				header_dict = dict(temp_headers)
				content_length = int(header_dict.get('content-length', 0))
				if len(body) >= content_length:
					return status_line, temp_headers, body[:content_length]
			
		raise BadRequestException
	
	def parse_request(self, request):
		try:
			status_and_headers, body = request.split('\r\n\r\n', 1)
		except ValueError:
			raise BadRequestException
		status_and_headers = status_and_headers.split('\r\n')
		status_line, headers = status_and_headers[0], status_and_headers[1:]
		return status_line, headers, body
		
	
	def method_and_path_from_line(self, first_line):
		try:
			method, path, _ = first_line.split(' ', 2)
			path = self.parse_and_normalize_path(path)
			return method, path
		except ValueError:
			raise BadRequestException
		except:
			raise
	
	def parse_and_normalize_path(self, path):
		p = re.compile('^/([\w\-.~/]|%[0-9A-Fa-f]{2})*$')
		if not p.match(path):
			raise BadRequestException
		
		def percent_decode(m):
			s = m.group(1)
			return s[1:].decode('hex')
		
		decoded_path = re.sub('(%[0-9A-Fa-f]{2})', percent_decode, path)
		normalized_path = os.path.normpath(decoded_path)
		
		return normalized_path
	
	def route_request(self):
		""" Parses the first line, and hands off the connection to either
			the static file handler or the cgi handler. """
		
		# Get entire http request: status_line, headers, body
		try:
			status_line, headers, body = self.read_and_parse_request()
		except socket.timeout:
			HTTP_Responder(self.socket).reply_timed_out()
			return
		except BadRequestException:
			HTTP_Responder(self.socket).reply_invalid_request()
			return
		
		# Split status line into method and path
		try:			
			method, path = self.method_and_path_from_line(status_line)
		except BadRequestException:
			HTTP_Responder(self.socket).reply_invalid_request()
			return
		
		# Route request to the CGI or static handler
		if path.startswith('/cgi-bin/'):
			handler = CGI_handler(method, path, headers, body, self.socket)
		else:
			handler = Static_handler(method, path, headers, body, self.socket)
		
		handler.handle_request()
	


class Handler_thread(threading.Thread):
	def run(self, client_socket):
		new_handler = HTTP_handler(client_socket)
		new_handler.route_request()