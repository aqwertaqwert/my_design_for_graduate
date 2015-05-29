import BaseHTTPServer
import sys
import pdb

HOST_NAME = ''
PORT_NUMBER = 8009

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_GET(self):
		self.log_message("Command: %s Path: %s Headers: %r" %(self.command, self.path, self.headers.items()))
		if(self.path[:7]=="/pslist"):
			vmname = self.path[8:]	
			self.sendPsList( vmname)
	def sendPsList(self, vmname):
			self.sendPage("text/html", "2819 sshd;2919 ps; 2911 java;")
	def sendPage(self, type, body):
		self.send_response(200)
		self.send_header("Content-type", type)
		self.send_header("Content-length", str(len(body)) )
		self.end_headers()
		self.wfile.write(body)
def httpd():
	server_class = BaseHTTPServer.HTTPServer
	Httpd = server_class((HOST_NAME, PORT_NUMBER), Handler)
	try:
		Httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()
	
if __name__=='__main__':
	httpd()
		
