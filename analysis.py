
from multiprocessing import Queue
import json
from pprint import pprint
import codecs

class HuntVTAnalysis():
    #q = Queue()

    def __init__(self):
        pass
    
    def run(self):
        pass


class HuntAnalysis():

    qprocs = Queue()
    qdns = Queue()
    qaccounts = Queue()
    qlocal_admins = Queue()
    qnetstat = Queue()
    qdisks = Queue()

    def __init__(self):
        pass
        
    def initializeData(self):
        pass
        
    def analyzeProcesses(self, data):
        pass
        
    def analyzeDNS(self, data):
        obj_name = 'DisplayDNS'
        if obj_name in data:
            line = 'hostname'
            for k in data[obj_name][0]:
                line += "," + k
            print line
            for a in data[obj_name]:
                line = self.hostname
                for k in a:
                    line += "," + str(a[k])
                print line
        
    def analyzeNetstat(self, data):
        obj_name = 'Netstat'
        if obj_name in data:
            line = 'hostname'
            for k in data[obj_name][0]:
                line += "," + k
            print line
            for a in data[obj_name]:
                line = self.hostname
                for k in a:
                    line += "," + str(a[k])
                print line
        
    def analyzeAccounts(self, data):
        obj_name = 'Accounts'
        if obj_name in data:
            line = 'hostname'
            for k in data[obj_name]['LocalAccounts'][0]:
                line += "," + k
            print line
            for a in data[obj_name]['LocalAccounts']:
                line = self.hostname
                for k in a:
                    line += "," + str(a[k])
                print line

    def processSurveys(self, surveyFiles):
        pass
        
    def processOne(self, survey_file):
        fh = codecs.open(survey_file, encoding='utf16')
        data = json.load(fh)
        #pprint(data)
        self.hostname = data['Hostname']
        for k in data:
            print k
        self.analyzeAccounts(data)
        


#HuntVTAnalysis()
v = HuntAnalysis()
v.processOne("results/SurveyResults-10.1.1.20.json")
