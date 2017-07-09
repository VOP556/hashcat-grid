#!/usr/bin/env python
import boinc_path_config
import os, time, sys, signal, subprocess
import assimilator
from hashcat_workgenerator import Generator
from Boinc import *
'''
example to start a hashcat round: 
bin/hashcat.py -a 1 -m 0 --rules work/rules --dictionary work/dictionary --hashes work/hashes --potfile-path results/potfile
'''
class NewHashcat():
    def __init__(self):
        self.parse_args(sys.argv[1:])
        database.connect()
        self.init_db()
        database.close()
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
            if arg == '-a':
                arg = args.pop()
                self.attack_mode = int(arg)
            elif arg == '-m':
                arg = args.pop()
                self.hash_mode = int(arg)
            elif arg == '--rules':
                arg = args.pop()
                self.global_rules_path = arg
            elif arg == '--potfile-path':
                arg = args.pop()
                self.global_potfile_path = arg
            elif arg == '--dictionary':
                arg = args.pop()
                self.global_wordlist_path = arg
            elif arg == '--hashes':
                arg = args.pop()
                self.hashes_path = arg
            else:
                print ("Unrecognized arg: %s\n", arg)
                print "Usage: hashcat.py -a <attack_mode> -m <hash_mode> --rules <path to rules file> --potfile-path <path to potfile> --dictionary <path to dictionary> --hashes <path to hashes>"

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

    def init_db(self):

        #count the dictionary
        print "Get dictionary count for {}... \n".format (self.global_wordlist_path)
        self.__wordlist_count = int(subprocess.check_output("wc -l "+Generator.CWD+self.global_wordlist_path+" | cut -d ' ' -f1", shell=True))
        print "Found {} Words in Dictionary {}\n".format(self.__wordlist_count, self.global_wordlist_path)

        #make rules unique and count the rules
        print "Get rules count for {}... \n".format(self.global_rules_path)
        self.make_unique(self.global_rules_path)
        self.__rules_count = int(subprocess.check_output("wc -l "+Generator.CWD + self.global_rules_path+" | cut -d ' ' -f1", shell=True))
        print "Found {} rules in rules-file {}\n".format(self.__rules_count, self.global_rules_path)

        #make the hashes unique
        self.make_unique(self.hashes_path)
        #make the potfile unique
        self.make_unique(self.global_potfile_path)

        hashcat_instance = database.Hashcat(global_wordlist_index=0,
                                            global_wordlist_path=self.global_wordlist_path,
                                            global_wordlist_count=self.__wordlist_count,
                                            global_rules_path=self.global_rules_path,
                                            global_rules_count=self.__rules_count,
                                            hash_mode=self.hash_mode,
                                            attack_mode = self.attack_mode,
                                            global_potfile_path=self.global_potfile_path,
                                            global_hashes_path=self.hashes_path,
                                            create_time=int(time.time()))
        hashcat_instance.commit()



def main():
    hashcat_instance=NewHashcat()

if __name__ == '__main__':
    main()