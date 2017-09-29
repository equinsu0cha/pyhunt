
from pyhunt.deploy import WMIEXEC
from pyhunt.deploy_smb import CMDEXEC
from multiprocessing import Process, Pool
from time import sleep

class HuntScan:
    def __init__(self, usr, pwd, domain, hashes=''):
        self.targets = []
        self.__currentpath = ''
        self.surveyfile = "survey/survey.ps1"
        self.tgtdestdirectory = "c:\\windows\\temp"
        self.__status = {}
        self.requiredfiles = []
        self.components = []
        self.__receiver = None
        self.__username = usr
        self.__password = pwd
        self.__domain = domain
        self.__hashes = hashes
        self.protocol = "SMB"
        self.shell = None

    def run(self):
        try:
            if self.__hashes == '':
                if self.protocol == "WMI":
                    executer = WMIEXEC('dir', self.__username, self.__password, self.__domain, None, None, "ADMIN$", scanObject=self)
                else:
                    executer = CMDEXEC(self.__username, self.__password, self.__domain, None, None, None, None, "SHARE", "ADMIN$", 445, scanObject=self)

            else:
                if self.protocol == "WMI":
                    executer = WMIEXEC('dir', self.__username, '', self.__domain, self.__hashes, None, "ADMIN$", scanObject=self)
                else:
                    executer = CMDEXEC(self.__username, self.__password, self.__domain, self.__hashes, None, None, None, "SHARE", "ADMIN$", 445, scanObject=self)
            
            
            threads = []
            cap = 1
            running = 0
            for t in self.targets:
                p = Process(target=executer.run, args=(t,))
                p.start()
                threads.append(p)
                running += 1
                
            for p in threads:
                p.join()
                

        except (Exception, KeyboardInterrupt), e:
            import traceback
            print traceback.print_exc()
            print str(e)
        
    def addTargetList(self, tgt):
        self.targets = tgt
        
    def __str__(self):
        return self.__domain + "\\" + self.__username + " " + str(self.__targets)

#h = HuntScan("user", "pw", "localhost", "")
#h.addTargetList(["192.168.149.141"])
#h.addTargetList(["10.1.1.20"])
#h.run()
