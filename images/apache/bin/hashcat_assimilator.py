#!/usr/bin/env python
import boinc_path_config
import assimilator
import os
import xml.etree.ElementTree as ET
import subprocess
import shutil
from Boinc import *
import hashcat_workgenerator

class hashcat_assimilator(assimilator.Assimilator):
    def __init__(self):
        assimilator.Assimilator.__init__(self)
    #thanks to bdice for these two methods
    #https://boinc.berkeley.edu/dev/forum_thread.php?id=10543

    def get_absolute_path(self, name):
        fanout = int(self.config.uldl_dir_fanout)
        hashed = self.filename_hash(name, fanout)
        updir = self.config.upload_dir
        result = os.path.join(updir, hashed, name)
        return result

    def get_multiple_file_paths(self, canonical_result):
        result_files = dict()
        rootxml = ET.fromstringlist(['<root>', canonical_result.xml_doc_in, '</root>'])
        resultxml = rootxml.find('result')
        for file_ref in resultxml.iter('file_ref'):
            file_name = file_ref.find('file_name').text
            open_name = file_ref.find('open_name').text
            result_files[open_name] = self.get_absolute_path(file_name)
        return result_files



    def assimilate_handler(self, wu, results, canonical_result):
        #get the hostid
        host_id = canonical_result.host.id
        self.logNormal("[%s] ClientID:[%s]\n", wu.name, host_id)
        #get the outputfiles
        output_files_dict = self.get_multiple_file_paths(canonical_result)
        potfile = file(output_files_dict['potfile'])
        benchmark = subprocess.check_output("tail -n60 "+output_files_dict['stdout.txt'] + " | grep Speed" , shell=True)
        speed = 0
        #get the speed of benchmarked client
        speed = benchmark.split(":")[-1].split()[0]
        speed_factor = benchmark.split(":")[-1].split()[1]
        if "kH" in speed_factor:
            speed_factor = float(1000)
        elif "MH" in speed_factor:
            speed_factor = float(1000*1000)
        else:
            speed_factor = float(1)
        speed = float(speed) * speed_factor
        self.logNormal("[%s] Client Speed:[%f]\n", wu.name, speed)
        #get the hashcat-instance-id from wu_name
        hashcatid = wu.name.split("_")[2]
        self.logDebug("[%s] HashcatID: [%s]\n",wu.name,hashcatid)
        #write speed to database
        database.Hashcat_Hosts.clear_cache()
        try:
            hashcat_hosts = database.Hashcat_Hosts.find()
        except:
            hashcat_hosts = database.Hashcat_Hosts.find()

        for host in hashcat_hosts:
            if int(host.hashcat.id) == int(hashcatid) and int(host.host.id) == int(host_id):
                host.speed = speed
                host.commit()
        #update potfile
        with open((hashcat_workgenerator.Generator.CWD+hashcat_workgenerator.Generator.POTFILE), "a+") as result_potfile:
           for potfile_line in potfile:
               #print result_potfile_line
               if potfile_line not in result_potfile.read():
                   self.logNormal("[%s] Hash recovered:  [%s]", wu.name, potfile_line)
                   #hash_value = potfile_line.split(":")[0]
                   #word_value = potfile_line.split(":")[1]
                   #word_db = database.Word(word=word_value)
                   #potfile_db = database.Hash(hash=hash_value, recovered=1, password=word_value)
                   result_potfile.write(potfile_line)
        os.system("cat "+output_files_dict['potfile']+" >> /root/project/results/potfile")
        gen = hashcat_workgenerator.Generator()
        gen.make_unique("/root/project/results/potfile")
 

if __name__ == '__main__':
     asm = hashcat_assimilator()
     asm.run()


