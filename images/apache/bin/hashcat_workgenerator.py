#!/usr/bin/env python
import boinc_path_config
import os, time, sys, signal, subprocess
import assimilator
from Boinc import *
class Generator():
    CWD = "/root/project/"
    WORK = 60 #seconds to calculate words for work
    POTFILE = 'results/potfile'
    DICTIONARY = 'work/dictionary'
    HASHES = 'work/hashes'
    RULES = 'work/rules'
    def __init__(self):
        self.__hashes = None
        self.__rules = None
        self.__rules_count = 0 
        self.__dictionary = None 
        self.__potfile = None
        self.__index = 0
        self.__lastpattern = ''
        self.__wordlist_count = 0
        self.__hashcat_id = 0
        self.log=sched_messages.SchedMessages()
        self.STOP_TRIGGER_FILENAME = boinc_project_path.project_path('stop_daemons')
        self.pass_count = 0
        self.caught_sig_int = False
        self.appname = 'hashcat'
        self.sleep_interval = 10
        os.chdir(Generator.CWD)

    def check_stop_trigger(self):
        """
        Stops the daemon when not running in one_pass mode
        There are two cases when the daemon will stop:
           1) if the SIGINT signal is received
           2) if the stop trigger file is present
        """

        try:
            junk = open(self.STOP_TRIGGER_FILENAME, 'r')
        except IOError:
            if self.caught_sig_int:
                self.logCritical("Caught SIGINT\n")
                sys.exit(1)
        else:
            self.logCritical("Found stop trigger\n")
            sys.exit(1)

    def sigint_handler(self, sig, stack):
        """
        This method handles the SIGINT signal. It sets a flag
        but waits to exit until check_stop_trigger is called
        """
        self.logDebug("Handled SIGINT\n")
        self.caught_sig_int = True

    def parse_args(self, args):
        """
        Parses arguments provided on the command line and sets
        those argument values as member variables. Arguments
        are parsed as their true types, so integers will be ints,
        not strings.
        """

        args.reverse()
        while(len(args)):
            arg = args.pop()
            if arg == '-sleep_interval':
                arg = args.pop()
                self.sleep_interval = float(arg)
            elif arg == '-d':
                arg = args.pop()
                self.log.set_debug_level(arg)
            elif arg == '-app':
                arg = args.pop()
                self.appname = arg
            else:
                self.logCritical("Unrecognized arg: %s\n", arg)
    '''
    def init_db(self):
        hashcat_instance = database.Hashcat(global_wordlist_index=0,
                                            global_wordlist_path=Generator.DICTIONARY,
                                            global_rules_path=Generator.RULES,
                                            hash_mode=0,
                                            create_time=int(time.time()))
        hashcat_instance.commit()
    '''
    def syncdb_hashcat_host(self, hostid, hashcatid):
        database.Hashcat_Hosts.clear_cache()
        contains = False
        for hashcat_host in database.Hashcat_Hosts.iterate():
            if hashcat_host.host.id == hostid and  hashcat_host.hashcat.id == hashcatid:
                contains = True
        if contains:
            return
        else:
            hashcat_host = database.Hashcat_Host(hostid=hostid,
                                                 hashcatid=hashcatid)
            hashcat_host.commit()
            
    def update_self(self, hashcat_instance):
        #update the dictionary
        if self.__dictionary != hashcat_instance.global_wordlist_path or self.__dictionary == None:
            self.__dictionary = hashcat_instance.global_wordlist_path
        #update the wordlist index
        if self.__index == 0 or self.__index != hashcat_instance.global_wordlist_index:
            self.__index = hashcat_instance.global_wordlist_index
        #update the wordlist count
        if self.__wordlist_count == 0 or self.__wordlist_count != hashcat_instance.global_wordlist_count:
            self.__wordlist_count = hashcat_instance.global_wordlist_count
        #update the potfile-path
        if self.__potfile == None or self.__potfile != hashcat_instance.global_potfile_path:
            self.__potfile = hashcat_instance.global_potfile_path
        #update the hashes-path
        if self.__hashes == None or self.__hashes != hashcat_instance.global_hashes_path:
            self.__hashes = hashcat_instance.global_hashes_path
        #update the rules
        if self.__rules == None or self.__rules != hashcat_instance.global_rules_path:
            self.__rules = hashcat_instance.global_rules_path
        #update the rules count        
        if self.__rules_count != hashcat_instance.global_rules_count:
            self.__rules_count = hashcat_instance.global_rules_count
             

    def run(self):
        """
        This function runs the class in a loop unless the
        one_pass or one_pass_WU_N flags are set. Before execution
        parse_args() is called, the xml config file is loaded and
        the SIGINT signal is hooked to the sigint_handler method.
        """
        self.parse_args(sys.argv[1:])
        self.config = configxml.default_config().config


        signal.signal(signal.SIGINT, self.sigint_handler)

        # do one pass or execute main loop
        # main loop
        while(1):
            self.check_stop_trigger()
            try:
                database.connect()
            except:
                self.logCritical("Can't connect to database\n")
                time.sleep(self.sleep_interval)
                continue
            workdone = self.do_pass()
            database.close()
            time.sleep(self.sleep_interval)
    
    def do_pass(self):
        """
        This method scans the database for hosts to generate work for
        Calls check_stop_trigger before doing any work.
        """

        did_something=False
        # check for stop trigger
        self.check_stop_trigger()
        self.pass_count += 1
        n = 0
        hashcat_instance_count = database.Hashcats.count()
        self.logDebug("Hashcat Instances: [%d]\n", hashcat_instance_count)
        #if hashcat_instance_count == 0:
        #    self.init_db()
        #    hashcat_instance_count = database.Hashcats.count()
        #    self.logDebug("Hashcat Instances updated: [%d]\n", hashcat_instance_count)
        hosts_count = database.Hosts.count()
        database.Assignments.clear_cache()
        database.Workunits.clear_cache()
        assignments = database.Assignments.find()
        self.logDebug("pass %d, hosts %d\n", self.pass_count, hosts_count)
        for hashcat in range(0,hashcat_instance_count):
            #update self 
            self.__hashcat_id = hashcat+1
            self.update_self(database.Hashcats[hashcat+1])
            self.statistics()
            for host in range(0,hosts_count):
                assignments_for_host = 0
                for assignment in assignments:
                    if assignment.target_id == (host+1):
                        if assignment.workunit.assimilate_state == boinc_db.ASSIMILATE_INIT:
                                assignments_for_host += 1
                self.logDebug("Host [%d] Assigned Work: [%d]\n", (host+1), assignments_for_host )
                if assignments_for_host < 2:
                    try:
                        host_object = database.Hosts[host+1]
                    except:
                        host_object = database.Hosts[host+1]
                    #get the speed from hashcat_host_table and create host if not exist
                    self.syncdb_hashcat_host((host+1), (hashcat+1))
                    speed = float(0)
                    for instance in database.Hashcat_Hosts.iterate():
                        if instance.host.id == (host+1) and instance.hashcat.id == (hashcat+1):
                            speed = instance.speed
                    self.logDebug("Host [%d] Speed: [%f]\n", (host+1), speed)
                    words_rules = self.calculate_work(speed)
                    self.generate_work(words_rules, (host+1))     
        return did_something

    def statistics(self):
        try:
            hosts = database.Hashcat_Hosts.find()
        except:
            hosts = database.Hashcat_Hosts.find()

        i=0
        for host in hosts:
            if host.hashcat.id == self.__hashcat_id:
                i=i+1
        start_time = float(database.Hashcats[self.__hashcat_id].create_time)
        now_time = time.time()
        duration = now_time - start_time
        start_time = time.strftime('%a, %d %b %Y %H:%M:%S',time.gmtime(start_time))
        duration = time.strftime('%H:%M:%S',time.gmtime(duration))
        self.logNormal('---------STATS Hashcat Instance [%d]----------\n', self.__hashcat_id)
        self.logNormal('Words:    [%d]  Done:[%d]  Left:[%d]\n', self.__wordlist_count, self.__index, (self.__wordlist_count-self.__index))
        self.logNormal('Hosts:    [%d]\n', i)
        self.logNormal('Rules:    [%d]\n', self.__rules_count)
        self.logNormal('Hashes:   [%d]  Recovered: []  Left:[]\n', i)
        self.logNormal('Starttime:[%s]  Duration:[%s]  Left:[]\n', start_time, duration)
        self.logNormal('---------STATS Hashcat Instance [%d]----------\n', self.__hashcat_id)


    def calculate_work(self, speed):
        '''
        returns the amount of words to be delivered to a host with speed and rules
        depending if it is a fast hash-algorithm (MH/s) or a slow hash-algorithm (H/s)
        or a middle fast hash it returns more or less words/rules
        '''
        words = 0
        rules = 0
        ''' 
        if speed >= float(1000) and speed < float(1000 * 1000):
            self.logDebug("Generating work for middle fast speed of [%d H/s]\n", int(speed))
            #middle fast hash -> send more words with half the count of rules
            rules = self.__rules_count / 2
            words = (Generator.WORK * int(speed)) / rules
    
        elif speed >= float(1000*1000):
            self.logDebug("Generating work for fast speed of [%d H/s]\n", int(speed))
            #fast hash -> send more words with only 1 rule
            rules = 1
            words = (Generator.WORK * int(speed)) / rules
        '''

        if speed == float(0):
            self.logDebug("Generating work for benchmarking Host\n")
            #client is not benchmarked -> send 0 words and 0 rules
            pass
        else:
            self.logDebug("Generating work for slow speed of [%d H/s]\n", int(speed))
            #slow hash -> send the words and all rules
            rules = self.__rules_count
            words = (Generator.WORK * int(speed)) / rules

        return (words,rules)
    
    def stage_file(self, file):
        self.logNormal("Staging [%s]\n", file)
        proc = subprocess.Popen([
                        'bin/stage_file', 
                        '--verbose', 
                        file], 
                        stdout=subprocess.PIPE)

        stdout_value = proc.communicate()[0]
        #self.logDebug("%s\n",stdout_value)
    
    def create_work(self, work, hostid, wu_name):
        self.logNormal("Create Work for Host [%d]\n", hostid)
        proc = subprocess.Popen([
                        'bin/create_work',
                        '--appname', 'hashcat',
                        '--target_host', str(hostid),
                        '--wu_name', wu_name,
                        work['dictionary_file'].split("/")[-1], 
                        work['hashes_file'].split("/")[-1], 
                        work['rules_file'].split("/")[-1], 
                        work['potfile'].split("/")[-1],
                        work['options_file'].split("/")[-1]
                        ],
                        stdout=subprocess.PIPE)

        stdout_value = proc.communicate()[0]
        self.logNormal("Work created:  [%s]\n", wu_name)

    def make_unique(self,inputfile):
        '''
        ensures that inputfile is present and content is unique
        '''
        my_set=set()
        try:
            with open(inputfile) as file:
               for line in file:
                   my_set.add(line)
        except IOError:
               pass
        with open(inputfile, "w") as file:
               pass
        with open(inputfile, "a") as file:
            for line in my_set:
                file.write(line)
        return open(inputfile)

    def generate_work(self, words_rules, hostid):
        '''
        creates work for the number of words and rules given
        startindex for dictionary is Generator.INDEX
        updates Generator.INDEX
        '''
        self.logDebug("Words: [%d] Rules: [%d] HostID: [%d]\n", words_rules[0], words_rules[1], hostid)
        wu_name = self.appname+"_wu"+"_"+str(self.__hashcat_id)+"_"+str(hostid)+"_"+str(time.time())
        work = {
            'rules_file': "work/"+wu_name+"_rules",
            'dictionary_file': "work/"+wu_name+"_dictionary",
            'potfile': "work/"+wu_name+"_potfile",
            'hashes_file': "work/"+wu_name+"_hashes",
            'options_file': "work/"+wu_name+"_options"
        }
        #create the files
        for key in work:
            with open(work[key], "w") as file:
                pass
        if words_rules[0] == 0 and words_rules[1] == 0:
            #create empty work
            hashcat_instance = database.Hashcats[self.__hashcat_id]
            options = ''.join(['-m ', str(hashcat_instance.hash_mode),
                ' -b '])
            #self.logDebug("options: [%s]",options)
            with open(work['options_file'], 'a') as options_file:
                options_file.write(options)

            for key in work:
                self.stage_file(work[key])
            #time.sleep(self.sleep_interval)

            self.create_work(work, hostid, wu_name)
        else:
            hashcat_instance = database.Hashcats[self.__hashcat_id]
            start_rules_index = hashcat_instance.global_rules_index
            start_wordlist_index = hashcat_instance.global_wordlist_index
            #check if dictionary exhausted and switch to bruteforce-mode
            if start_wordlist_index >= self.__wordlist_count:
                self.logNormal("Wordlist exhaustest, switching to bruteforce mode\n")
                self.generate_bruteforce_work(words_rules, hostid)
                return
            
            end_wordlist_index = start_wordlist_index + words_rules[0]
            end_rules_index = start_rules_index + words_rules[1]

            #get the words
            self.logNormal("Writing new dictionary... \n")
            if (start_wordlist_index+1+words_rules[0]) >self.__wordlist_count:
                words_rules = list(words_rules)
                words_rules[0] = self.__wordlist_count - (start_wordlist_index+1)
                words_rules = tuple(words_rules)
            os.system('tail -n+'+str(start_wordlist_index+1)+ " "+self.__dictionary+' | head -n'+ str(words_rules[0])+' | sort -u >'+ str(' /root/project/'+work['dictionary_file'])+' 2>/dev/null')
            #tail -n+$START $DICT | head -n$LINES | sort -u > "./work/$WORDLIST"
            '''

            self.logNormal("Writing new dictionary ...\n")
            with open(self.__dictionary) as dictionary:
                with open(work['dictionary_file'], 'a') as new_dictionary:
                    for line, i in enumerate(dictionary):
                        if (i > int(start_wordlist_index)) and (i <= int(end_wordlist_index)):
                            new_dictionary.write(line)
                        elif i > int(end_wordlist_index):
                            break
            '''
            #get the rules
            self.logNormal("Writing new rules-file ...\n")
            #os.system('cp /root/project/'+self.__rules+' /root/project/'+work['rules_file'])
            with open(self.__rules) as rules:
                with open(work['rules_file'], 'a') as new_rules:
                    for i, line in enumerate(rules):
                        new_rules.write(line)
            
            #get the hashes
            self.logNormal("Writing new hashes-file ...\n")
            with open(self.__hashes) as hashes:
                with open(work['hashes_file'], 'a') as new_hashes:
                    for i, line in enumerate(hashes):
                        new_hashes.write(line)
            
            #get the potfile
            self.logNormal("Writing new potfile-file ...\n")
            with open(self.__potfile) as potfile:
                with open(work['potfile'], 'a') as new_potfile:
                    for i, line in enumerate(potfile):
                        new_potfile.write(line)
            #update index in db

            #hashcat_instance.global_rules_index = end_rules_index
            
            hashcat_instance.global_wordlist_index = end_wordlist_index
            hashcat_instance.commit()

            #get the options
            options1 = ''.join(['-m ', str(hashcat_instance.hash_mode),
                ' -b '])

            options2 = ''.join(['-a ', str(hashcat_instance.attack_mode),
                ' -m ', str(hashcat_instance.hash_mode),
                ' --outfile-format ', str(hashcat_instance.outfile_format),
                ' --debug-mode ', str(hashcat_instance.rule_debug),
                ' -r rules --potfile-path potfile --debug-file=debug hashes dictionary '])
            
            options = ':'.join([options1, options2])
            #for option in hashcat_instance.options.split():
            #    options += str(" --"+option+" ")
            #self.logDebug("options: [%s]",options)
            with open(work['options_file'], 'a') as options_file:
                options_file.write((options))
            #create the work
            for key in work:
                self.stage_file(work[key])
            #time.sleep(self.sleep_interval)
            self.create_work(work, hostid, wu_name)




    def generate_bruteforce_work(self, words_rules, hostid):
        '''
        is called when dictionary is exhausted and generates a bruteforce
        dictionary for the hostid and saves the last pattern
        '''
        self.logDebug("Bruteforce-Mode not yet implemented... nothing done\n")
        pass

    def _writeLog(self, mode, *args):
        """
        A private helper function for writeing to the log
        """
        self.log.printf(mode, *args)

    def logCritical(self, *messageArgs):
        """
        A helper function for logging critical messages
        """
        self._writeLog(sched_messages.CRITICAL, *messageArgs)

    def logNormal(self, *messageArgs):
        """
        A helper function for logging normal messages
        """
        self._writeLog(sched_messages.NORMAL, *messageArgs)

    def logDebug(self, *messageArgs):
        """
        A helper function for logging debug messages
        """
        self._writeLog(sched_messages.DEBUG, *messageArgs)


def main():
    gen=Generator()
    gen.run()

if __name__ == '__main__':
    main()