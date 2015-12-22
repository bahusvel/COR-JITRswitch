__author__ = 'denis'
import socket
import sys
import os

server_address = './socket'

# Make sure the socket does not already exist
try:
	os.unlink(server_address)
except OSError:
	if os.path.exists(server_address):
		raise

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
print('starting up on %s' % server_address)
sock.bind(server_address)
sock.listen(1)
while True:
	# Wait for a connection
	print('waiting for a connection')
	connection, client_address = sock.accept()
	try:
		print('connection from', client_address)

		# Receive the data in small chunks and retransmit it
		data = connection.recv(5).decode("ascii")  # START, CLEAR, FLUSH
		print('received "%s"' % data)
		if data == "START":
			print('start the queue')
		elif data == "CLEAR":
			print('clear the queue')
		elif data == "FLUSH":
			print("flush the queue")
		else:
			print("wrong data")
	finally:  # Clean up the connection
		connection.close()
