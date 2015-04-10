import socket
import sys

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_address = ('localhost', 9000)
print >>sys.stderr, 'connection to %s port %s' %server_address
sock.connect(server_address)

try:
    message = raw_input('> ')
    print >>sys.stderr, 'sending "%s"'%message
    sock.sendall(message)

    amount_received = 0
    amount_expected = len(message)
    while amount_received < amount_expected:
        data = sock.recv(10240) 
        amount_received += len(data)
        print >>sys.stderr, 'received "%s"' % data

finally:
    print >>sys.stderr, 'closing socket'
    sock.close()
