__author__ = 'denis'
import socket
import sys

# Create a UDS socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = './socket'
print('connecting to %s' % server_address)
try:
	sock.connect(server_address)
except Exception:
	print("oops")

try:
	# Send data
	message = "START".encode("ascii")
	print('sending "%s"' % message)
	sock.sendall(message)
finally:
	print('closing socket')
	sock.close()
