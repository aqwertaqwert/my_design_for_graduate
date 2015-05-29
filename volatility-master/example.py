#!/usr/bin/python
#  -*- mode: python; -*-

#pylint: disable-msg=C0111
import thread
from threading import Thread
import pdb
import sys
import kvm
import logging
import unix
import time
import os

if sys.version_info < (2, 6, 0):
    sys.stderr.write("Volatility requires python version 2.6, please upgrade your python installation.")
    sys.exit(1)

try:
    import psyco #pylint: disable-msg=W0611,F0401
except ImportError:
    pass

if False:
    # Include a fake import for things like pyinstaller to hit
    # since this is a dependency of the malware plugins
    import yara

import textwrap
import volatility.conf as conf
#config = conf.ConfObject()
import volatility.constants as constants
import volatility.registry as registry
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.debug as debug

import volatility.addrspace as addrspace
import volatility.commands as commands
import volatility.scan as scan
from VmCheckConfig import GetVmCheckConfigs
import VmCheckConfig as VmCheckConfig
#config.add_option("INFO", default = None, action = "store_true",
                  #cache_invalidator = False,
                  #help = "Print information about all registered objects")
class Volatility(object):

	
	config = conf.ConfObject()
	cmds = {}
	profile = "--profile=Linuxcentos5_5x86"

	def Is_SystemCallHooked(self, vmname):

	   data = self.Check_SystemCall( vmname)
	   for ( table_name, i, call_addr, hooked) in data:
		if hooked != 0:
			return True
	   return False

	def Check_SystemCall(self, vmname):
	  #for (table_name, i, call_addr, hooked) in data:
            #if hooked == 0:
	   return self.ExecuteCommand(vmname, "linux_check_syscall")
	   
	def Check_ProcessName(self, vmname):
	   data = self.ExecuteCommand(vmname, "linux_pslist")
	   list = []
	   for task in data:
		list.append(str(task.comm))
	   return list
		
	def Check_Process(self, vmname):
	   return self.ExecuteCommand(vmname, "linux_pslist")
	def Check_ProcessDump(self, vmname, pname):
	   outfile = "./tmp/"+pname+".2"
	   if not os.path.exists("./tmp"):
		os.makedirs("./tmp")
 
	   self.ExecuteCommand(vmname, "linux_dump_proc_map",pname, outfile )

	def ExecuteCommand(self, vmname, command, pname = None, outfile=None):
	    location = "-l vmi://"+vmname;
	    
	    argv = self.profile+" "+location+" ";
	    if pname :
		argv+="-n "+pname+" "
	    if outfile :
		argv+="-O "+outfile+" "
	    argv+=command
 	    #pdb.set_trace()
	    self.config.parse_options_from_string(argv, False)
	    module  = self.GetModule(self.config)
	    return self.ExecuteModule(module, argv)

	def GetModule(self, config):
		for m in config.args:
			if m in self.cmds.keys():
			    module = m
			    return module 

		if not module:
		#config.parse_options()
			debug.error("You must specify something to do (try -h)")
		
		
	def ExecuteModule(self, module, argv):
		    if not module:			
			debug.error("You must specify something to do (try -h)")
		    try:
			if module in self.cmds.keys():
			    command = self.cmds[module](self.config)
			    #print dir(config)

			    #print config.args
			    ## Register the help cb from the command itself
			    #self.config.set_help_hook(obj.Curry(command_help, command))
			    #config.parse_options()
			    self.config.parse_options_from_string(argv)
			    #pdb.set_trace()

			    if not self.config.LOCATION:
				debug.error("Please specify a location (-l) or filename (-f)")

			    data = command.execute_call()
			    return data
			    #for task in data:
			#	print str(task.comm)+"\t"+str(task.pid)
		    except exceptions.AddrSpaceError, e:
		   	print e
#		    except (exceptions.VolatilityException,exceptions.AddrSpaceError) as e:
			#print e

	def __init__(self):	

	    # Get the version information on every output from the beginning
	    # Exceptionally useful for debugging/telling people what's going on
	    #sys.stderr.write("Volatile Systems Volatility Framework {0}\n".format(constants.VERSION))
	    #sys.stderr.flush()

	    self.config.add_option("INFO", default = None, action = "store_true",
			  cache_invalidator = False,
			  help = "Print information about all registered objects")

	    # Setup the debugging format
	    debug.setup()
	    # Load up modules in case they set config options
	    registry.PluginImporter()

	    ## Register all register_options for the various classes
	    registry.register_global_options(self.config, addrspace.BaseAddressSpace)
	    registry.register_global_options(self.config, commands.Command)

		# Reset the logging level now we know whether debug is set or not
	    debug.setup(self.config.DEBUG)
	    
	    #pdb.set_trace()
	    
	    ## Try to find the first thing that looks like a module name
	    self.cmds = registry.get_plugin_classes(commands.Command, lower = True)
	    
class MonitorCmd(object):
	rpmap= {} # [pname] = ploc
	isRestoreSnapShot = False	
	isRestartVM = False
	vmname = ""
	kvm_host = kvm.KVM(unix.Local())

	def __init__(self, vmname, hostinfo):
		self.vmname = vmname	
		self.user = hostinfo['username'] 
		self.password= hostinfo['password'] 
		self.ip = hostinfo['ip'] 

	def AddRestartProcess(self, pname, ploc):
		if pname not in self.rpmap:
			self.rpmap[pname] = ploc	
	def SetRestoreSnapShot(self):
		self.isRestoreSnapShot = True
	def SetRestartVM(self):
		self.isRestartVM = True
	def Execute(self):
		print "Execute monitor cmd"
		print "Action "+self.vmname
		
		if self.isRestoreSnapShot:
			print "\tRestoreing from snapshot"
			#r = self.kvm_host.destroy(self.vmname)			
			
		elif self.isRestartVM:
			print "\tRestarting vm"
			r = self.kvm_host.destroy(self.vmname)			
			logging.info(r[1])
			r = self.kvm_host.start(self.vmname)
			logging.info(r[1])
		elif self.rpmap:	
			print "\tRestarting process\t" 
	#		pdb.set_trace()
			h = unix.Remote()
			h.connect(self.ip,username=self.user, password=self.password)
			msg = self.vmname+" Restarting process:\t" 
			rplist = []
			for (k, v)  in sorted(self.rpmap.items()):
				rplist.append(v)
 				
			#thread.start_new_thread(ExecuteCMDInVm, (self.rpmap, msg, h))
			try:
				Thread(target=ExecuteCMDInVm, args=(msg,rplist, h)).start()
			except Exception, errtxt:
			 	logging.error(errtxt)
def ExecuteCMDInVm(msg, rplist, h):
	for v in rplist:
		r = h.execute(v)	
		print msg+"\t"+v+"\t"+str(r[0])

	
def CheckVMS():

	vmcfgs = GetVmCheckConfigs("./vms.cfg")
	#pdb.set_trace()
	kvm_host = kvm.KVM(unix.Local())
	kvm_vms = kvm_host.vms
#	vmcfgs = [vm01config, vm02config ]
	for vmcfg in vmcfgs:
		if vmcfg.GetVmName() not in kvm_vms :
			logging.warning(vmcfg.GetVmName()+" is not available!")
			vmcfgs.remove(vmcfg.GetVmName())

	while True:
		for vmcfg in vmcfgs:
			if kvm_host.state(vmcfg.GetVmName()) == 'shut off':
				logging.warning(vmcfg.GetVmName()+" is not running")				
				continue

			try:
				print "Checking VMs:"+" "+vmcfg.GetVmName()
				hostinfo = vmcfg.GetHostInfo()
				vmCmd = MonitorCmd( vmcfg.GetVmName(), hostinfo)	
				CheckVMProcess(vmcfg, vmCmd)
				CheckVMSystemCall(vmcfg, vmCmd)
				CheckVMProcMemory(vmcfg, vmCmd)
				vmCmd.Execute()
			except exceptions.AddrSpaceError:
				logging.error(vmcfg.GetVmName()+" profile is not valid")
			except Exception, e:
				logging.exception(e)
		print "sleep 20"
		time.sleep(20)
# can move this method to vmCmd
def ProcessActionStr(pname, action, vmCmd):

	logging.info(pname+" is stopped, need "+action[0])
	if action[0] == "restartP":
		vmCmd.AddRestartProcess(pname, action[1])
	elif action[0] == "restoreV":
		vmCmd.SetRestoreSnapShot()
	elif action[0] == "restartV":
		vmCmd.SetRestartVM()
	else :
		logging.error("Unknowing action")
		
def CheckVMProcess(vmcfg, vmCmd):
	print "\t Checking Processes"
	logging.info("\t Checking Processes")		
	vmProcessList = volatility.Check_ProcessName(vmcfg.GetVmName())
	processMap = vmcfg.GetProcessMap()	
	#pdb.set_trace()

	for k,v in sorted(processMap.items()):
		#print k+" "+v
		if k not in vmProcessList:
			ProcessActionStr(k, v, vmCmd) 
def CheckVMSystemCall(vmcfg, vmCmd):
	print "\t Checking System call"	
	logging.info("\t Checking System call")		
	if volatility.Is_SystemCallHooked(vmcfg.GetVmName())	:
		vmCmd.SetRestartVM()
	   
def CheckVMProcMemory(vmcfg, vmCmd):
	print "\t Checking procs memory"
	logging.info("\t Checking procs memory")

	#need
	volatility.Check_ProcessDump(vmcfg.GetVmName(), "sshd")
if __name__ == "__main__":
    #config.add_help_hook(list_plugins)
    logging.basicConfig(level=logging.INFO, filename='csdvmm.log')
    logging.info('Starting program')
	 
    try:
	
        volatility = Volatility() 
	#pdb.set_trace()	
	CheckVMS()
    except Exception, ex:
        #if config.DEBUG:
            debug.post_mortem()
	    logging.exception(ex)
        #else:
        #    raise
    except KeyboardInterrupt:
        print "Interrupted"
