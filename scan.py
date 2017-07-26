
from pyhunt.deploy import WMIEXEC
from multiprocessing import Process, Pool
from time import sleep

class HuntScan:
    def __init__(self, usr, pwd, domain, hashes=''):
        self.__targets = []
        self.__currentpath = ''
        self.surveyfile = "survey/survey.ps1"
        self.tgtdestdirectory = "c:\\windows\\temp\\pyhunt"
        self.__status = {}
        self.__requiredfiles = []
        self.__components = []
        self.__receiver = None
        self.__username = usr
        self.__password = pwd
        self.__domain = domain
        self.__hashes = hashes
        self.shell = None

    # def f(x):
        # self.executer.run(x)

    def run(self):
        try:
            if self.__hashes == '':
                executer = WMIEXEC('dir', self.__username, self.__password, self.__domain, None, None, "ADMIN$", scanObject=self)
            else:
                executer = WMIEXEC('dir', self.__username, '', self.__domain, self.__hashes, None, "ADMIN$", scanObject=self)
            
            # p = Pool(processes=5)
            # p.map(self.f, self.__targets)
            
            threads = []
            cap = 1
            running = 0
            for t in self.__targets:
                p = Process(target=executer.run, args=(t,))
                p.start()
                threads.append(p)
                running += 1
                print "starting " + t
                
            for p in threads:
                p.join()
                
            #executer.run("10.1.1.34", self)

        except (Exception, KeyboardInterrupt), e:
            #import traceback
            #print traceback.print_exc()
            print str(e)
        
    def addTargetList(self, tgt):
        self.__targets += tgt
        
    def __str__(self):
        return self.__domain + "\\" + self.__username + " " + str(self.__targets)