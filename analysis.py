
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
        
    def analyzeDNS(self, data, output_file):
        obj_name = 'DisplayDNS'
        if obj_name in data:
            line = 'hostname'
            for k in data[obj_name][0]:
                line += "," + k
            print line
            output_file.write(line+"\n")
            for a in data[obj_name]:
                line = self.hostname
                for k in a:
                    line += "," + str(a[k])
                print line
                output_file.write(line+"\n")
        
    def analyzeNetstat(self, data, output_file):
        obj_name = 'Netstat'
        if obj_name in data:
            line = 'hostname'
            for k in data[obj_name][0]:
                line += "," + k
            print line
            output_file.write(line+"\n")
            for a in data[obj_name]:
                line = self.hostname
                for k in a:
                    line += "," + str(a[k])
                print line
                output_file.write(line+"\n")
        
    def analyzeAccounts(self, data, output_file):
        obj_name = 'Accounts'
        if obj_name in data:
            line = 'hostname'
            for k in data[obj_name]['LocalAccounts'][0]:
                line += "," + k
            print line
            output_file.write(line+"\n")
            for a in data[obj_name]['LocalAccounts']:
                line = self.hostname
                for k in a:
                    line += "," + str(a[k])
                print line
                output_file.write(line+"\n")

    def processSurveys(self, surveyFiles):
        pass
        
    def processOne(self, survey_file):
        fh = codecs.open(survey_file, encoding='utf16')
        data = json.load(fh)
        output_file_prefix = survey_file[:-5]
        #pprint(data)
        self.hostname = data['Hostname']
        for k in data:
            print k
        output_file = open(output_file_prefix+"-accounts.csv",'w')
        self.analyzeAccounts(data, output_file)
        output_file.close()

        output_file = open(output_file_prefix+"-dns.csv",'w')
        self.analyzeDNS(data, output_file)
        output_file.close()

        output_file = open(output_file_prefix+"-netstat.csv",'w')
        self.analyzeNetstat(data, output_file)
        


#HuntVTAnalysis()
v = HuntAnalysis()
#v.processOne("results/SurveyResults-10.1.1.20.json")
v.processOne("results/SurveyResults-172.16.2.22.json")
