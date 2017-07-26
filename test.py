#!/usr/bin/python



from __future__ import print_function
from pyhunt.scan import HuntScan

import hashlib,binascii
from passlib.hash import lmhash

import sys

scan = None

def newScan(cmd):
    print("new scan!!")
    dom = raw_input("Domain:  ")
    usr = raw_input("Username:  ")
    pwd = raw_input("Password (leave blank and enter hashes next):  ")
    if pwd == '':
        hashes = raw_input("Hashes (format:  lm:ntlm):  ")
    scan = HuntScan(usr, pwd, dom, hashes)
    
def set(cmd):
    if cmd[1] == "targets":
        tgts = cmd[2].split(",")
        #TODO: Validate targets
        print("targets  =>  ", tgts)
        scan.addTargetList(tgts)
    
def exit(cmd):
    sys.exit(0)
    
def show(cmd):
    print(scan)
    
def hashpw(cmd):
    print("Original password:  "+cmd[1])
    ntlmhash = hashlib.new('md4', cmd[1].encode('utf-16le')).digest()
    lm = lmhash.hash(cmd[1])
    print (str(lm)+":"+binascii.hexlify(ntlmhash))
    
def gohunt(cmd)
    scan.run()

while True:
    c = raw_input("hunt >  ")
    cmd = c.split(' ')
    options = {'new' : newScan,
            'set' : set,
            'exit' : exit,
            'show' : show,
            'hunt' : gohunt,
            'hash' : hashpw
    }
    try:
        options[cmd[0]](cmd)
    except KeyError:
        print("Command not found...try 'help'")
    
# s.addTarget('10.1.1.34')
# s.addTarget('10.1.1.20')
s.addTargetList(['10.1.1.34', '10.1.1.20'])

#print s.__password
#print s
s.run()
#print s