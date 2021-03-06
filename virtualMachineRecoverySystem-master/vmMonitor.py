#coding=utf-8
#!/usr/bin/python
#  -*- mode: python; -*-
#pylint: disable-msg=C0111
from threading import Thread
import string
import re
import pdb
import sys
import kvm
import unix
import os.path as path
import time
import logging
import volatility.exceptions as exceptions
from vmInspection import VmInspection
from vmCheckStatus import VmCheckStatus
import volatility.plugins.linux.pslist as linux_pslist
import hashlib
import vmrsConfig

class VmMonitor(object):
	vmcfgs = {}
	vmInspection = VmInspection() 
	vmpList=[]
	kvm_host = kvm.KVM(unix.Local())
	AllList=[]
	MonitPMD5 = []
	#sys_call_table_MD5 = "NULL"
	#self.vmProcessMap = {}

	def __init__(self, vmcfgs):
		
		kvm_vms = self.kvm_host.vms

		for vmcfg in vmcfgs:
			vmname = vmcfg.GetVmName()
			if  vmname not in kvm_vms :
				logging.warning(vmname+" is not available!")
				vmcfgs.remove(vmname)
			else:
				self.vmcfgs[vmname] = vmcfg

	def Execute(self):
		vmstatus = {}

		for(vmname, vmcfg) in sorted(self.vmcfgs.items()): 
			status = VmCheckStatus()
			logging.info("Checking VM: "+vmname)
			state = self.kvm_host.state(vmname) 
			
			if state != kvm.RUNNING:
				logging.warning(vmname +" is in status "+state) 
				status.VmState = state
				vmstatus[vmname] = status
				continue
			try:
				VmData = self.GetVMData(vmname)  #yield <type 'generator'> 迭代器 不能重复使用
				monitorPlist = self.GetMonitorPlist(vmname)            #得到监控进程信息
 				AllList = self.CaculateData(VmData,monitorPlist,vmname)       #一次计算所有想要信息  
				vmpList = AllList[0]
				mplist = self.CheckVMMissingProcesses(vmname,vmpList,monitorPlist)
				status.MissingProcesses = mplist;
				#mplist2 = self.CheckHiddenProcesses(vmname,vmpList)
				#status.HiddenProcesses = mplist2;
				monitPlistcode = AllList[1]
				ModifiedProcessList = self.CheckModifiedProcesses(vmname,monitPlistcode)
				status.ModifiedProcess = ModifiedProcessList;

				status.isSystemCallHooked = self.CheckVMSystemCall(vmname)
				print status.isSystemCallHooked
				print "xxxsssfghh"

				status.ZombieProcesses = self.CheckZombieProcesses(vmname)
			except exceptions.AddrSpaceError, e:
				logging.exception(vmcfg.GetVmName()+" profile is not valid")
				
				status.ProfileValid = False
			except Exception, e:
				logging.exception(e)
			
			vmstatus[vmname] = status
		return vmstatus
	def CheckVMSystemCall(self, vmname):
		logging.info("\t Checking System call")		
		return self.vmInspection.IsSystemCallHooked(vmname, self.vmcfgs[vmname].Profile,self.vmcfgs[vmname].sys_call_table_MD5)

	def CheckZombieProcesses(self, vmname):
	#	self.vmInspection.DumpProcess(vmname, "sshd", self.vmcfgs[vmname].Profile)
		zombieProcesses = []
		pmap = self.vmcfgs[vmname].GetMonitorProcessMap()	
		logDict = {}
		for(k,v) in sorted(pmap.items()):
			if not v[2] == "":
				logDict[v[2]] = k	

		try:
			if logDict:
				h = unix.Remote()
				hostinfo = self.vmcfgs[vmname].GetHostInfo()
				h.connect(hostinfo['ip'], username=hostinfo['username'], password=hostinfo['password'])
			for(logfile,processname) in sorted(logDict.items()):# iterate the valid logfile
				if self._check_zombie_log(logfile, h):
					zombieProcesses.append(processname)
		except Exception, errtxt:
				logging.error(errtxt)

		return zombieProcesses

	def _check_zombie_log(self, logfile, host):
		result = False
		try:
			cmd = "echo $(( $(date +%s) - $(stat -c '%Y' {0}) ))".format(logfile)

			info = host.execute(cmd)	

			if(int(info[1]) > vmrsConfig.LOG_FILE_ZOMBIE_TIME):
				result = True	
		except Exception, errtxt:
				logging.error(errtxt)
				result = False
		return result
		
	def CheckVMMissingProcesses(self, vmname,vmpList,monitorPlist):
		logging.info("\t Checking VM missing Processes")		
		vmMissingProcess = []
		#vmpList = self.GetVMProcessName(vmname)				

		for p in monitorPlist:
			found = False
			for pfullname in vmpList:
				#print pfullname
				#print "xxxxxxxxxxxxxxxx"
				if pfullname.find(p)>=0 :
					found = True
					break
			if(not found):
				vmMissingProcess.append(p)
		return vmMissingProcess 


	def GetMonitorPlist(self, vmname):
		#monitorPlist = []
		#vmpList = self.GetVMProcessName(vmname)				
		pmap = self.vmcfgs[vmname].GetMonitorProcessMap()	
		monitorPlist = []
		for(k,v) in sorted(pmap.items()):
			monitorPlist.append(k)
		return monitorPlist 

	def GetMonitorPMD5list(self, vmname):
		#monitorPlist = []
		#vmpList = self.GetVMProcessName(vmname)				
		pmap = self.vmcfgs[vmname].GetMonitorProcessMap()	
		PMD5list = {}
		for (k,v) in pmap.items():
			PMD5list[k] = v[3]
		print PMD5list 
		return PMD5list 

	def CheckHiddenProcesses(self, vmname, vmpList):
		logging.info("\t Checking VM hidden Processes")	
		vmHiddenProcess = []
		pscontent = self.GetVMProcessName2(vmname)
		#print pscontent	
		content = ''.join(vmpList)
		patt = re.compile(r"\'(.*?)\'", re.I|re.X)
		list = patt.findall(content)
		#list.append("ahahahaaahhaahh")          
		#print list
		
		for p in list:
			#print p
			p = p.rstrip()

			if (p == '/csd/HiddenProcess'):
				vmHiddenProcess.append(p)
			x = (p in pscontent)
			#print x
			if (not x) :
				if( p != '/usr/sbin/packagekitd' and p !='sleep 60' and p!='pickup -l -t fifo -u' and p!='[pgrep]' and p!='[pickup]' and p!= '[crond]' and 'awk -v' not in p and p!= '[ksmtuned]' and p != '[awk]') :
					vmHiddenProcess.append(p)
				
		print vmHiddenProcess
		return vmHiddenProcess


	def GetVMProcesses(self, vmname):
		vmProcesses = self.vmInspection.GetProcesses(vmname, self.vmcfgs[vmname].Profile)
		return vmProcesses


	def GetVMProcessName(self, datas):
		return self.vmInspection.GetProcessName(datas)


	def GetVMData(self, vmname):
		return self.vmInspection.GetVmData(vmname, self.vmcfgs[vmname].Profile)

	def CaculateData(self, datas,monitorPlist,vmname):
		return self.vmInspection.Caculate(datas,monitorPlist,vmname)

	def ExecuteCMDInVm(self, msg, cmds,ip, usr,pwd ):
		h = unix.Remote()
		hostinfo = self.vmcfgs[vmname].GetHostInfo()
		h.connect(hostinfo['ip'], username=hostinfo['username'], password=hostinfo['password'])
		logging.info("ExecuteCMDInVm")
		for v in cmds:
			#pdb.set_trace()
			r = h.execute(v)	
			logging.info(r)
			logging.info(msg+"\t"+v+"\t"+str(r[0]))
			try:
				try:
					sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
					server_address = ('localhost', 8010)
					sock.connect(server_address)
					sock.sendall(r)
    					sock.sendall(msg+"\t"+v+"\t"+str(r[0]))
				finally:
   	 				sock.close()
			except:
				print""		

	def GetVMProcessName2(self,vmname):
		pslist = []
		h = unix.Remote()
		hostinfo = self.vmcfgs[vmname].GetHostInfo()
		h.connect(hostinfo['ip'], username=hostinfo['username'], password=hostinfo['password'])
		cmds = "ps aux"
		data = h.execute(cmds)
		
		content = data[1]

		#content = ''.join(data)
		#print "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
		#m = re.search('csd',content)
		#print m
		#m.group()
		#for name in data:# task, name
		#patt = re.compile(r"\[(.*?)\]", re.I|re.X)
		#mlist = patt.findall(content)
		#print mlist
		#print "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
		#for line in content.split("\n"):
			#pslist.append(line)
			#print line
		#pslist.remove("([task_struct task_struct] @ 0x88003D75EAE0, '/usr/libexec/gvfsd-metadata ')")
		#length = len(pslist)
		#print "XXXXXXXX",length
		return content


	def GetmonitPlistcode(self, datas , monitorPlist):
		return self.vmInspection.GetPlistcode(datas , monitorPlist)


	def CheckModifiedProcesses(self , vmname , monitPlistcode ):
		logging.info("\t Checking VM Modified Processes")		
		ModifiedProcess = []
		PMD5list  = self.GetMonitorPMD5list(vmname)
		for (k,v) in monitPlistcode.items():
			if PMD5list[k] == 'NULL':
				self.vmcfgs[vmname].processMap[k][3] = monitPlistcode[k]
				pass
			elif PMD5list[k] != monitPlistcode[k]:
				ModifiedProcess.append(k)
			else: 
				pass
							
		return ModifiedProcess 


