#!/usr/local/bin/python

import sys
import struct

def generate_header(size, offset=54):
	header = 'BM'
	header += struct.pack('<I', size)
	header += '\x00'*4
	header += struct.pack('<I', offset)
	return header

def generate_image_header(width, height, bitsperpixel=24):
	header = struct.pack('<IIIHHIIIIII', 40, width, height, 1, bitsperpixel, 0, 0, 0, 0, 0, 0)
	return header

def generate_solid_color(color, width, height):
	return color*(width*height)

if __name__ == '__main__':
	color = sys.stdin.read(3)
	width, height = 16, 16
	image = b''
	image_header = generate_image_header(width, height)
	pixels = generate_solid_color(color, width, height) # 0xbgr
	size = 14 + 40 + 3*width*height
	header = generate_header(size)
	image = header + image_header + pixels
	sys.stdout.write('Content-type: image/bmp\r\n\r\n')
	sys.stdout.write(image)