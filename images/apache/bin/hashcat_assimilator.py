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
        benchmark = subprocess.check_output("head -n58 "+output_files_dict['stdout.txt'] + " | grep Speed" , shell=True)
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
 

    def assimilate_handler_old(self, wu, results, canonical_result):
        work_seconds = 60 #change for longer work to be done by clients
        #ensure uniqueness of input files instead of dictionary (too big)
        self.make_unique("work/hashes")
        self.make_unique("work/rules")
        self.make_unique("results/potfile")
        self.make_unique("work/potfile")
        #get the hostid
        host_id = canonical_result.host.id
        self.logNormal("[%s] ClientID:[%s]\n", wu.name, host_id)
        #get the output files
        output_files_dict = self.get_multiple_file_paths(canonical_result)
        potfile = file(output_files_dict['potfile'])
        benchmark = file(output_files_dict['benchmark'])
        #get the speed of benchmarked client
        for line in benchmark:
            if "Speed" in line:
                speed = line.split(":")[-1].split()[0]
                speed_factor = line.split(":")[-1].split()[1]
                if "kH" in speed_factor:
                    speed_factor = float(1000)
                elif "MH" in speed_factor:
                    speed_factor = float(1000*1000)
                else:
                    speed_factor = float(1)
                speed = float(speed) * speed_factor
                self.logNormal("[%s] Client Speed:[%f]\n", wu.name, speed)
       #calculate the work and prepare the dictionary and rules
        rules_count = 0
        dictionary_count = 0
        start_index = 0
        end_index = 0
        words = 0
        try:
            with open("work/rules") as rules:
                for i, line in enumerate(rules):
                    rules_count = i
            self.logNormal("[%s] Rules Count:[%d]\n", wu.name, rules_count)
            with open("work/dictionary") as dictionary:
                for i, line in enumerate(dictionary):
                    dictionary_count = i
            self.logNormal("[%s] Words in dictionary:[%d]\n", wu.name, dictionary_count)
            words = (speed*work_seconds) / rules_count #number of words to fill work_seconds
            self.logNormal("[%s] Words for [%d]s work: [%d]\n", wu.name, work_seconds, words)
        except IOError:
            self.logNormal("[%s] No dictionary or rules file found\n", wu.name)
         #get startindex and endindex for new dictionary
        try:
            with open("work/index") as index_file:
                start_index = index_file.read()
        except IOError:
            with open("work/index", "w") as index_file:
                index_file.write("0")
            with open("work/index") as index_file:
                start_index = index_file.read()
        end_index = int(start_index) + int(words)
        # no new work if dictionary is exhausted
        if int(start_index) >= int(words):
            self.logNormal("[%s] Dictionary exhausted... generating no new work\n", wu.name)
            return
        self.logNormal("[%s] Index for dictionary START:[%s]\n", wu.name, start_index)
        self.logNormal("[%s] Index for dictionary END:[%s]\n", wu.name, end_index)
        #create dictionary for new work if not exsists
        new_dictionary = "dictionary_"+wu.name
        try:
            with open("work/"+new_dictionary) as new_dictionary_file:
                new_dictionary_file.read()
        except IOError:
            try:
                with open("work/dictionary") as dictionary:
                    with open("work/"+new_dictionary, "w") as new_dictionary_file:
                        for i, line in enumerate(dictionary):
                            if (i > int(start_index)) and (i <= int(end_index)):
                                start_index = str(i)
                                new_dictionary_file.write(line)
            except IOError:
                self.logCritical("[%s] IOError for dictionary or new_dictionary\n", wu.name)
         #save index in file
            try:
                with open("work/index", "w") as index_file:
                    index_file.write(start_index)
            except IOError:
                self.logCritical("[%s] IOError for index_file\n", wu.name)
         #stage the new dictionary
        self.logNormal("[%s] Generating new work...\n", wu.name)
        self.logNormal("[%s] Staging [%s]\n", wu.name, new_dictionary)

        proc = subprocess.Popen([
                       'bin/stage_file',
                       '--verbose',
                        str('work/'+new_dictionary)],
                        stdout=subprocess.PIPE)
        stdout_value = proc.communicate()[0]
       #stage the hashes
        new_hashes = "hashes_"+wu.name
        self.logNormal("[%s] Staging [%s]\n", wu.name, new_hashes)
        shutil.copy2("work/hashes", ("work/"+new_hashes))
        proc = subprocess.Popen([
                        'bin/stage_file',
                        '--verbose',
                        str('work/'+new_hashes)],
                        stdout=subprocess.PIPE)

        stdout_value = proc.communicate()[0]
        #stage the rules
        new_rules = "rules_"+wu.name
        self.logNormal("[%s] Staging [%s]\n", wu.name, new_rules)
        shutil.copy2("work/rules", ("work/"+new_rules))
        proc = subprocess.Popen([
                        'bin/stage_file',
                        '--verbose',
                        str('work/'+new_rules)],
                        stdout=subprocess.PIPE)

        stdout_value = proc.communicate()[0]
        #print stdout_value
        self.logNormal("[%s] Generating new potfile\n", wu.name)
        #stage the new potfile
        contains = False
        with open("results/potfile", "a+") as result_potfile:
           for potfile_line in potfile:
               #print result_potfile_line
               if potfile_line not in result_potfile.read():
                   self.logNormal("[%s] Hash recovered:  [%s]", wu.name, potfile_line)
                   result_potfile.write(potfile_line)
        self.make_unique("results/potfile")
        new_potfile = "potfile_"+wu.name
        self.logNormal("[%s] Staging [%s]\n", wu.name, new_potfile)
        shutil.copy2("results/potfile", ("results/"+new_potfile))
        proc = subprocess.Popen([
                        'bin/stage_file',
                        '--verbose',
                        str('results/'+new_potfile)],
                        stdout=subprocess.PIPE)
        stdout_value = proc.communicate()[0]
        #create new work for this client
        self.logNormal("[%s] Create Work: \n", wu.name)
        proc = subprocess.Popen([
                        'bin/create_work',
                        '--appname', 'hashcat',
                        '--target_host', str(host_id),
                        str(new_dictionary), new_hashes, new_rules, new_potfile],
                        stdout=subprocess.PIPE)

        stdout_value = proc.communicate()[0]
        self.logNormal("[%s] Work created:  [%s]", wu.name, stdout_value)

if __name__ == '__main__':
     asm = hashcat_assimilator()
     asm.run()


