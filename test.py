#!/usr/bin/python



from __future__ import print_function
from pyhunt.scan import HuntScan

import hashlib,binascii
from passlib.hash import lmhash

import sys
import os

class HuntCmdLine:
    scan = None

    def newScan(self, cmd):
        print("new scan!!")
        dom = raw_input("Domain:  ")
        usr = raw_input("Username:  ")
        pwd = raw_input("Password (leave blank and enter hashes next):  ")
        hashes = ''
        if pwd == '':
            hashes = raw_input("Hashes (format:  lm:ntlm):  ")
        self.scan = HuntScan(usr, pwd, dom, hashes)
        
    def set(self, cmd):
        if cmd[1] == "targets":
            tgts = cmd[2].split(",")
            #TODO: Validate targets
            print("targets  =>  ", tgts)
            self.scan.addTargetList(tgts)
        
    def exit(self, cmd):
        sys.exit(0)
        
    def show(self, cmd):
        print(self.scan)
        
    def hashpw(self, cmd):
        print("Original password:  "+cmd[1])
        ntlmhash = hashlib.new('md4', cmd[1].encode('utf-16le')).digest()
        lm = lmhash.hash(cmd[1])
        print (str(lm)+":"+binascii.hexlify(ntlmhash))
        
    def gohunt(self, cmd):
        self.scan.run()

    def __init__(self):

        log_path = "./log/"
        result_path = "./results"
        if not os.path.exists(log_path):
            os.mkdir(log_path)
        if not os.path.exists(result_path):
            os.mkdir(result_path)

        while True:
            c = raw_input("hunt >  ")
            cmd = c.split(' ')
            options = {'new' : self.newScan,
                    'set' : self.set,
                    'exit' : self.exit,
                    'show' : self.show,
                    'hunt' : self.gohunt,
                    'hash' : self.hashpw
            }
            try:
                options[cmd[0]](cmd)
            except KeyError:
                print("Command not found...try 'help'")

HuntCmdLine()
# s.addTarget('10.1.1.34')
# s.addTarget('10.1.1.20')
#s.addTargetList(['10.1.1.34', '10.1.1.20'])

#print s.__password
#print s
#s.run()
#print s
