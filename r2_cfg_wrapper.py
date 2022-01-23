# Copyright (C) 2017 Thomas Rinsma / Riscure
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# System imports
from binascii import crc32

# Packages
import r2pipe
import tempfile

# calculate CFG topology
from igraph import Graph, InternalError

class R2CFGWrapper:
    """
    Grab CFG and other data from r2.
    """

    def __init__(self, filename):
        # Load the binary
        self.r2 = r2pipe.open(filename, ["-e bin.cache=true"])

        # Perform analysis
        # TODO: What types of analysis?
        self.r2.cmd("aaaa")

        # Grab the function list
        self.functions = self.r2.cmdj("aflj")

    def get_cyclomatic_complexity_list(self):
        return [f['cc'] for f in self.functions]

    def get_tiny_cfg(self):
        tiny_cfgs = list()
        for f in self.functions:
            agfg = self.r2.cmd("agfg @%s" % f['name'])
            
            with tempfile.NamedTemporaryFile() as fp:
                fp.write(agfg.encode())
                fp.seek(0)
                g = Graph.Read_GML(fp.name)
                fp.close()

            try:
                tinycfg = str()
                for clust in g.clusters().cluster_graph().get_edgelist():
                    tinycfg += str(clust[0]) + str(clust[1])
            except InternalError as e:
                tinycfg = None
        
            tiny_cfgs.append(tinycfg)
        
        return tiny_cfgs

    def get_cfg(self):
        return [self.r2.cmdj("agj @0x%x" % f['offset']) for f in self.functions]

    def get_bb_hashes(self):
        # CRC32 of the concatenation of all instruction types for every function
        for f in self.functions:
            fbb = self.r2.cmdj("agj @0x%x" % f['offset'])
            fops = []
            if len(fbb) < 1:
                continue
            for b in fbb[0]['blocks']:
                for i in b['ops']:
                    fops.append(i['type'])
            yield crc32(''.join(fops).encode())


    def read_function(self, function):
        return self.r2.cmdj("afij @0x%x" % function['offset'])
