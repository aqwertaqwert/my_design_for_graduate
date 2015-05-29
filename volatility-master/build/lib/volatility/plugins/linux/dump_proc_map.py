import sys
import os.path
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.proc_maps as linux_proc_maps
import pdb
import logging

class linux_dump_proc_map(linux_common.AbstractLinuxCommand):
    """ Writes selected process memory mappings to disk """

    def __init__(self, config, *args):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('PNAME', short_option = 'n', default = None, help = 'Filter by pname', action = 'store', type = 'str')
        self._config.add_option('OUTPUTFILE', short_option = 'O', default = None, help = 'Output File', action = 'store', type = 'str')

    def read_addr_range(self, task, start, end):
        pagesize = 4096 

        # set the as with our new dtb so we can read from userland
        proc_as = task.get_process_address_space()

        # xrange doesn't support longs :(
        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize
    def calculate(self):
	data = self._calculate()

	if not self._config.OUTPUTFILE:
            debug.error("Please specify an OUTPUTFILE")
       # elif os.path.exists(self._config.OUTPUTFILE):
       #     debug.info("Cowardly refusing to overwrite an existing file")
	#pdb.set_trace()
	logging.info("Writing to file: {0}\n".format(self._config.OUTPUTFILE))
        outfile = open(self._config.OUTPUTFILE, "wb")
        size = 0
        for page in data:
            size += len(page)
            outfile.write(page)
        outfile.close()
	logging.info("Wrote {0} bytes, in file {1}".format(size, self._config.OUTPUTFILE))

    def _calculate(self):
        linux_common.set_plugin_members(self)
        vmas = linux_proc_maps.linux_proc_maps(self._config).calculate()
	print "pname\t"+self._config.PNAME
        for (task, vma) in vmas:
            if not self._config.PNAME or self._config.PNAME==str(task.comm):
                for page in self.read_addr_range(task, vma.vm_start, vma.vm_end):
                    if page:
			yield page 

    def render_text(self, outfd, data):
        if not self._config.OUTPUTFILE:
            debug.error("Please specify an OUTPUTFILE")
        elif os.path.exists(self._config.OUTPUTFILE):
            debug.error("Cowardly refusing to overwrite an existing file")

        outfd.write("Writing to file: {0}\n".format(self._config.OUTPUTFILE))

        #outfile = open(self._config.OUTPUTFILE, "wb+")
        outfile = open(self._config.OUTPUTFILE, "wb")

        size = 0
        for page in data:
            size += len(page)
            outfile.write(page)
        outfile.close()
        outfd.write("Wrote {0} bytes\n".format(size))
