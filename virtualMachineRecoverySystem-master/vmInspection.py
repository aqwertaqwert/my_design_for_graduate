#!/usr/bin/python
# -*- coding: utf-8 -*-
#  -*- mode: python; -*-

#pylint: disable-msg=C0111

import sys
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
import hashlib
import textwrap
import volatility.conf as conf
import os
import re
import logging
import pdb
#config = conf.ConfObject()
# must be put before  registry
import volatility.constants as constants

profile_path="/soft/virtualMachineRecoverySystem-master/vol-profile/"
argv = ['main.py','--plugins='+profile_path] 
argvt = sys.argv  
sys.argv = argv
import volatility.registry as registry
sys.argv = argvt

import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.debug as debug

import volatility.addrspace as addrspace
import volatility.commands as commands
import volatility.scan as scan


class VmInspection(object):
		
	def IsSystemCallHooked(self, vmname, profile,sys_call_table_MD5):
	   self.profile = profile
	   print sys_call_table_MD5[0]
	   #ptint "sadsafsaaaaaaaaaaaaaaaa"
	   data = self._CheckSystemCall( vmname)
	   #print data
	   table = ""
	   for ( table_name, i, call_addr, hooked) in data:
		 table+=(str(call_addr))
	   #print table
	   tables = hashlib.md5(table).hexdigest().upper()
	   print tables
	   if(sys_call_table_MD5[0] =="NULL"):
	         sys_call_table_MD5[0] = str(tables)
		 print "xxxxxxxxxx"
		 return False
	   elif(sys_call_table_MD5[0] != str(tables)):
		   print "yyyyyy"
		   return True
	   else:
		   print "zzzzzzzzz"
		   return False
  

	def _CheckSystemCall(self, vmname):
	   return self._ExecuteCommand(vmname, "linux_check_syscall")

	def GetVmData(self, vmname, profile):
	   self.profile = profile
	   #data = self._ExecuteCommand(vmname, "linux_pslist")
	   datas = self._ExecuteCommand(vmname, "linux_psaux")
	   return datas
		
	def GetProcessName(self, datas):
	  # self.profile = profile
	   #data = self._ExecuteCommand(vmname, "linux_pslist")
	   #datas = self._ExecuteCommand(vmname, "linux_psaux")
	   list = []
     #      patt = re.compile(r"\[(.*?)\]", re.I|re.X)
      #     list = patt.findall(data)
	   for name in datas:# task, name 
		list.append(name[1])
		#print name[0]
		#print name[1]
		#print str(task)
		#task = data[0]
            #start = task.mm.start_code.v()
            #argv = proc_as.read(start, task.mm.end_code - task.mm.start_code)
            #if argv:
            	#code = " ".join(argv.split("\x00"))
            	#code = hashlib.md5(code).hexdigest().upper()
            #else:
                #code ="NULL"
		#list[data[1]] = data[2]
               # print str(data[1])
               # print str(data[2])
           #print data
           #length = len(list)
          # print "XXXXXXXX",length
	   return list


	def GetPlistcode(self, datas , monitorPlist):
		#monitorPlist = []
		#vmpList = self.GetVMProcessName(vmname)				)	
		monitPlistcode = {}
		
		for p in monitorPlist:
			code = "NULL"
			#print p
			for task,name in datas:
				#print name[1]
				#print "xxxxxxxxxxxxxxxx"
				if name.find(p)>=0 :
					proc_as = task.get_process_address_space()
					#print proc_as 
					#print "XXXXXXXXXXXXXXXXXXXXXXXXX"
        				if task.mm:
						start = task.mm.start_code.v()
						argv = proc_as.read(start, task.mm.end_code - task.mm.start_code)
						if argv:
							code = " ".join(argv.split("\x00"))
							#print code
							code = hashlib.md5(code).hexdigest().upper()
							#print code
						else:
                					code ="NULL"
        				else:
            				# kernel thread
						code = "NULL"
					break
				
			monitPlistcode[p] =code
		#print monitPlistcode	
		return monitPlistcode 


	def GetProcesses(self, vmname, profile):
	   logging.info(profile)
	   self.profile = profile
	   self.vmprocessMap[vmname] = self._ExecuteCommand(vmname, "linux_pslist")
	   logging.info(self.vmprocessMap[vmname])
	   return self.vmprocessMap[vmname] 

	def Caculate(self, datas ,monitorPlist ,vmname):
            logging.info("Caculate the vm data from "+vmname)
            vmpList = []
            monitPlistcode = {}
            monitorPlistcopy = monitorPlist[:]
		#print monitorPlistcopy
            for task,name in datas:
                vmpList.append(name)
                for p in monitorPlistcopy:
                    if name.find(p)>=0 :
                        monitorPlistcopy.remove(p)
                        #print monitorPlistcopy
                        proc_as = task.get_process_address_space()
                        if task.mm:
                            start = task.mm.start_code.v()
                            argv = proc_as.read(start, task.mm.end_code - task.mm.start_code)
                            if argv:
                                code = " ".join(argv.split("\x00"))
                                #print code
                                code = hashlib.md5(code).hexdigest().upper()
                                #print code
                            else:
                                code ="NULL"
                        else:
                            # kernel thread
                            code = "NULL"
                        monitPlistcode[p] =code
                        break
				
            print monitPlistcode
            #print vmpList
            return vmpList , monitPlistcode 
		

	def DumpProcess(self, vmname, pname, profile):
	   self.profile = profile
	   outfile = "./tmp/"+pname+".2"
	   if not os.path.exists("./tmp"):
		os.makedirs("./tmp")
 
	   self._ExecuteCommand(vmname, "linux_dump_proc_map",pname, outfile )

	def _ExecuteCommand(self, vmname, command, pname = None, outfile=None):
	    location = " -l vmi://"+vmname;
	    profile = " --profile "+self.profile 
	    #argv = self.plugin+profile+location+" ";
	    argv = profile+location+" ";
	   # pdb.set_trace()
	    if pname :
		argv+="-n "+pname+" "
	    if outfile :
		argv+="-O "+outfile+" "
	    argv+=command
 	    #pdb.set_trace()
	    self.config.parse_options_from_string(argv, False)
	    module  = self._GetModule(self.config)
	    #print argv
	    #print module
	    #print "sssssss"
	    return self._ExecuteModule(module, argv)

	def _GetModule(self, config):
		for m in config.args:
			if m in self.cmds.keys():
			    module = m
			    return module 

		if not module:
		#config.parse_options()
			debug.error("You must specify something to do (try -h)")
		
		
	def _ExecuteModule(self, module, argv):
		    if not module:			
			debug.error("You must specify something to do (try -h)")
		    try:
			if module in self.cmds.keys():
			    command = self.cmds[module](self.config)
			    #print command
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
	    self.config = conf.ConfObject()
	    self.cmds = {}
	    #self.profile = "--profile=Linuxcentos5_5x86"
	    self.vmprocessMap = {}

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
