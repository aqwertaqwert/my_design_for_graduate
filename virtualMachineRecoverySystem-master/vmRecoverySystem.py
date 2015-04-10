#!/usr/bin/python
#  -*- mode: python; -*-

#pylint: disable-msg=C0111

from threading import Thread
from vmMonitorCfg import VmMonitorCfg
from vmMonitor import VmMonitor
from vmRecoveryPolicy import VmRecoveryPolicy
import logging
import time
import socket
import sys

class VmRecoverySystem(object):
	
	def __init__(self):
		self.vmcfgs = VmMonitorCfg.GetVmMonitorCfgs("./vms.cfg")
		self.vmMonitor = VmMonitor(self.vmcfgs);
		self.vmRecoveryPolicy = VmRecoveryPolicy(self.vmcfgs)
	@property
	def Monitor(self):
		return self.vmMonitor	

	def Execute_forever(self):

		while True:
			validVmStatusDict = self.vmMonitor.Execute()
			
			for(vm, vmStatus) in sorted(validVmStatusDict.items()):
				logging.info("Vm checked status:"+vm+"\n"+vmStatus.ToString())
				#try:
					#try:
						#sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
						#server_address = ('localhost', 8010)
						#sock.connect(server_address)
    						#sock.sendall("Vm checked status:"+vm+"\n"+vmStatus.ToString())
					#finally:
   	 					#sock.close()
				#except:
					#print" "
			monitorCmds = self.vmRecoveryPolicy.Execute(validVmStatusDict)

			for(vm, cmd) in sorted(monitorCmds.items()):
				logging.info("Vm cmd:"+vm+"\n"+cmd.ToString())
				#try:
					#try:
						#sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
						#server_address = ('localhost', 8010)
						#sock.connect(server_address)
    						#sock.sendall("Vm checked status:"+vm+"\n"+vmStatus.ToString())
					#finally:
   	 					#sock.close()
				#except:
					#print""
			for (vmname, cmd) in sorted(monitorCmds.items()):
				cmd.Execute()	
			logging.info("sleep 160")
			time.sleep(160)
			
