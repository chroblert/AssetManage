import threading
import subprocess
import hashlib
from pathlib import Path
try:
    import xml.etree.CElementTree as ET
except:
    import xml.etree.ElementTree as ET
class config:
    nmapScanIPLimit = 20
    nmapScanThreadLimit = 20
    pass
class PortCheckThread(threading.Thread):
    def __init__(self,func,args,name=""):
        threading.Thread.__init__(self)
        self.func = func
        self.args = args
        self.result = None
        self.name = name
    def run(self):
        print("{} : start check port {} ".format(self.args[0],self.args[2]))
        self.result = self.func(self.args[1])
        print("{} : stop check port {} ".format(self.args[0],self.args[2]))

class PortCheck:
    def __init__(self,data={}):
        self.data = data
    def extractNmapInfo(self,file1):
        tree = ET.parse(file1)
        root = tree.getroot()
        hosts = root.findall("host")
        tmpList = []
        for host in hosts:
            ip = host.find("address").attrib['addr']
            ports = host.find("ports").findall("port")
            tmpDict = {}
            for port in ports:
                portID = port.attrib['portid']
                serviceName = port.find("service").attrib['name'] if "name" in port.find("service").attrib else "Null"
                productName = port.find("service").attrib['product'] if "product" in port.find("service").attrib else "Null"
                productVersion = port.find("service").attrib['version'] if "version" in port.find("service").attrib else "Null"
                # print("{} {} {} {} {}".format(ip,portID,serviceName,productName,productVersion))
                metaStr = ip+portID+serviceName+productName+productVersion
                h1=hashlib.md5()
                h1.update(metaStr.encode("utf-8"))
                hashstr = h1.hexdigest()
                tmpDict['hashstr'] = hashstr
                tmpDict['ip'] = ip
                tmpDict['port'] = portID
                tmpDict['serviceName'] = serviceName
                tmpDict['productName'] = productName
                tmpDict['productVersion'] = productVersion
                tmpList.append(tmpDict)
        return tmpList.copy()
    def enumXMLFile(self,pathstr="."):
        tmpList = list(Path(pathstr).glob("*.xml"))
        filenameList = []
        for i in tmpList:
            filenameList.append(i.name)
        return filenameList.copy()
    def portCheckSingleThread(self,argsstr=""):
        child = subprocess.Popen(args=argsstr,shell=True)
        child.wait()
        
    def portCheck(self,port=80,ipList=[]):
        # for i in list(range(0,len(ipList))):
        i = 0
        counter = 1
        threads = []
        nmapScanStrList = []
        while i < len(ipList):
            tmpCount = config.nmapScanIPLimit if len(ipList) - i > config.nmapScanIPLimit else len(ipList) - i
            # for j in range(1,tmpCount + 1):
            tmpList = ipList[i:i+tmpCount]
            ipListStr = " ".join(tmpList)
            nmapScanStr = "nmap -p {}  -sT -sV -Pn -n --open {} -oA ./metaNmapResult/{}_{} 2>&1 1>/dev/null".format(port,ipListStr,port,counter)
            # nmapScanStr = "echo {} {}".format(port,ipListStr)
            print(nmapScanStr)
            nmapScanStrList.append(nmapScanStr)
            i = i + tmpCount
            counter = counter + 1
        i = 0
        while i < len(nmapScanStrList):
            tmpCount = config.nmapScanThreadLimit if len(nmapScanStrList) - i > config.nmapScanThreadLimit else len(nmapScanStrList) - i
            for j in range(1,tmpCount + 1):
                t = PortCheckThread(func=self.portCheckSingleThread,args=(j,nmapScanStrList[i+j-1],port),name=str(j))
                threads.append(t)
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            i = i + tmpCount
        print("++++++++++++++OVER+++++++++++++++++++")
    def dirClean(self):
        tmp_dir3 = Path("./metaNmapResult")
        tmp_dir4 = Path("./bak")
        if not tmp_dir4.exists():
            tmp_dir4.mkdir()
        if tmp_dir3.exists():
            #child = subprocess.Popen(args="rm -rf ./metaNmapResult",shell=True)
            cmd="mv -f ./metaNmapResult ./bak/metaNmapResult_$(date +%Y%m%d%H%M%S)_bak"
            child = subprocess.Popen(args=cmd,shell=True)
            child.wait()
        tmp_dir3.mkdir()
    def check(self):
        self.dirClean()
        for port in self.data.keys():
            IPList = self.data[port]
            self.portCheck(port=port,ipList=IPList)
            print("{}:{}".format(port,",".join(IPList)))
        checkResList = []
        for filename in self.enumXMLFile(pathstr="./metaNmapResult"):
            tmpList = self.extractNmapInfo(file1="./metaNmapResult/"+filename)
            checkResList.extend(tmpList)
        return checkResList.copy()
    """检查IP是否开放了某些Port

    Args:
        data: 一个包含了IP和Port的Dict，格式为{"Port1":["ip1","ip2"],"Port2":["ip3","ip4"]}
    Returns:
        无
    Raise：
        IOError
    """