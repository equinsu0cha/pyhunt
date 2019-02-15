#!/usr/bin/python



from __future__ import print_function
from pyhunt.scan import HuntScan

import hashlib,binascii
from passlib.hash import lmhash

import sys
import os
import cmd
import getpass

class HuntCmdLine(cmd.Cmd):
    scan = None

    def emptyline(self):
        pass

    def do_new(self, cmd):
        print("new scan!!")
        dom = raw_input("Domain:  ")
        usr = raw_input("Username:  ")
#        pwd = raw_input("Password (leave blank and enter hashes next):  ")
        pwd = getpass.getpass("Password (leave blank and enter hashes next):  ")
        hashes = ''
        if pwd == '':
            hashes = raw_input("Hashes (format:  lm:ntlm):  ")
        self.scan = HuntScan(usr, pwd, dom, hashes)
        
    def do_set(self, cmdln):
        if self.scan == None:
            print("Scan not defined.  Use 'new' to define a new scan")
            return
        cmd = cmdln.split()
        if cmd[0] == "targets":
            print("List IP addresses or hostnames in a comma or space separated list.  Be careful of domain resolution problems.  You can also specify 'file:'")
            targetsRead = raw_input("Targets:  ")
            if targetsRead[0:5] == "file:":
                f = open(targetsRead[5:], 'r')
                tgts = f.readlines()
                tgts = [x.strip() for x in tgts]
            else:
                temp = targetsRead.replace(",", " ")
                tgts = temp.split()
            #TODO: Validate targets
            print("targets  =>  ", tgts)
            self.scan.addTargetList(tgts)
        elif cmd[0] == "protocol":
            print("Valid protocols are 'SMB' and 'WMI'")
            self.scan.protocol = raw_input("Protocol:  ")
        else:
            print("Variable name " + cmd[0] + " unknown")

        
    def do_exit(self, cmd):
        sys.exit(0)
        
    def do_show(self, cmd):
        print("\n" + str(self.scan) + "\n")
        
    def do_hashpw(self, cmd):
        origpw = raw_input("Original password:  ")
        ntlmhash = hashlib.new('md4', origpw.encode('utf-16le')).digest()
        lm = lmhash.hash(origpw)
        print (str(lm)+":"+binascii.hexlify(ntlmhash))
        
    def do_hunt(self, cmd):
        self.scan.run()

    def __init__(self):

        log_path = "./log/"
        result_path = "./results"
        if not os.path.exists(log_path):
            os.mkdir(log_path)
        if not os.path.exists(result_path):
            os.mkdir(result_path)
        cmd.Cmd.__init__(self)
        self.prompt = "hunt >  "
        self.cmdloop()

#        while True:
#            c = raw_input("hunt >  ")
#            cmd = c.split(' ')
#            options = {'new' : self.newScan,
#                    'set' : self.set,
#                    'exit' : self.exit,
#                    'show' : self.show,
#                    'hunt' : self.gohunt,
#                    'hash' : self.hashpw
#            }
#            try:
#                options[cmd[0]](cmd)
#            except KeyError:
#                print("Command not found...try 'help'")

if __name__ == '__main__':
    HuntCmdLine()
# s.addTarget('10.1.1.34')
# s.addTarget('10.1.1.20')
#s.addTargetList(['10.1.1.34', '10.1.1.20'])

#print s.__password
#print s
#s.run()
#print s
