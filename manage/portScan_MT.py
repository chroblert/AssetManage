import subprocess
import os
from pathlib import Path,PurePosixPath
import sqlite3
import hashlib
import threading
import multiprocessing
import time
from openpyxl import Workbook
try:
    import xml.etree.CElementTree as ET
except:
    import xml.etree.ElementTree as ET

class config:
    serverPortDBName="portinfo.db"
    scanLimit = 1000
    nmapScanLimit = 20
    restore = 1
    ThreadCount = 20
    @staticmethod
    def setScanLimit(masscanScanLimit=1000):
        if masscanScanLimit != "" and masscanScanLimit != None:
            config.scanLimit = masscanScanLimit
    @staticmethod
    def setNmapScanLimit(nmapScanLimit=20):
        if nmapScanLimit != "" and nmapScanLimit != None:
            config.nmapScanLimit = nmapScanLimit
    @staticmethod
    def setThreadCount(ThreadCount = 20):
        if ThreadCount != "" and ThreadCount != None:
            config.ThreadCount = ThreadCount

class MasscanThread(threading.Thread):
    def __init__(self,func,args,name='',):
        threading.Thread.__init__(self)
        self.func = func
        self.args = args
        self.name = name
        self.result = None

    def run(self):
        print("start:masscan {},thread {}".format(self.args[0],self.args[1]))
        self.result = self.func(self.args[0],self.args[2],)
        print("stop: masscan {},thread {}".format(self.args[0],self.args[1]))
class NmapThread(threading.Thread):
    def __init__(self,func,args,name = ''):
        threading.Thread.__init__(self)
        self.func = func
        self.args = args
        self.name = name
        self.result = None
    def run(self):
        print("start:nmap {} :thread{}".format(self.args[0],self.args[1]))
        self.result = self.func(self.args[0],)
        print("stop :nmap {} :thread{}".format(self.args[0],self.args[1]))
def masscan_one_port(port='80',ipList=[]):
    tmpList = ipList.copy()
    count = 0
    while len(tmpList) > 0:
        count += 1
        ipScanList = []
        if len(tmpList) >= config.scanLimit:
            for i in range(0,config.scanLimit):
                ipScanList.append(tmpList.pop())
        else:
            ipScanList = tmpList.copy()
            tmpList = []
        ipScanStr = ",".join(ipScanList)
        scanStr = "masscan -sS -Pn --open-only --rate=1000 -p" + str(port) + " " + ipScanStr +" --http-user-agent 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36' -oG " + str(port) + "_" + str(count) + ".txt 2>&1 1>/dev/null"
        # print(scanStr)
        child = subprocess.Popen(args = scanStr,shell=True)
        child.wait()
    return count
def set_portlist(scanType="all",start=1,end=65535,portList=[]):
    '''
    设置masscan扫描要用的portlist
    '''
    tmp = portList
    portList = []
    if scanType == "all":
        portList = range(start,end)
    elif scanType == "restore":
        # config.restore 是中断后恢复用的
        portList = range(config.restore,end)
    elif scanType == "list":
        portList=tmp
    elif scanType == "file":
        with open("portList.txt","r",encoding="utf-8") as f:
            tmpList = f.readlines()
        for port in tmpList:
            portList.append(port.repalce("\n",""))
    return list(portList).copy()
def set_iplist(type="file",iplist = []):
    '''
    设置要使用的iplist,以及对列表进行清洗，替换里面的"\n"
    '''
    if type == "file":
        with open("ipList.txt","r",encoding="utf-8") as f:
            # ipList = f.read()
            tmpList = f.readlines()
    elif type == "list":
        tmpList = iplist
    ipList = []
    for ip in tmpList:
        ipList.append(ip.replace("\n",""))
    return ipList.copy()
def get_ip_port_list(count,port):
    '''
    获取当前目录下，某端口所有的扫描文件内的ip。返回一个iplist
    '''
    ipWithPortList = []
    for i in range(1,count+1):
        fileName = str(port) + "_" + str(i) + ".txt"
        with open(fileName,"r",encoding="utf-8") as f:
            tmpList = f.readlines()
        for line in tmpList:
            if line.startswith("Host:"):
                ipWithPortList.append(line.split(" ")[1])
        # delete this file
        os.remove(fileName)
    return ipWithPortList.copy()
def check_dir_is_exist_or_create(dir1="./resultPort"):
    '''
    检查目录是否存在，若不存在则创建
    '''
    my_dir = Path(dir1)
    if not my_dir.exists():
        my_dir.mkdir()
def sort_and_store_masscan_res(type="port",ipWithPortList=[],port=''):
    '''
    将masscan扫描到的开放的某端口的所有ip，以ip或port分类存储
    '''
    if len(ipWithPortList) == 0:
        print("empty list")
        return False
    if type == "port":
        with open("./resultPort/" + str(port)+".txt","w",encoding="utf-8") as f:
            f.write("\n".join(ipWithPortList))
            f.write("\n")
        cpStr = "cp ./resultPort/"+str(port)+".txt ./tmpPortDir/"+str(port)+".txt"
        child=subprocess.Popen(args=cpStr,shell=True)
        child.wait()
    else:
        for ip in ipWithPortList:
            my_file1 = Path("./resultIP/" + str(ip) + ".txt")
            if my_file1.exists():
                with open("./resultIP/" + str(ip) + ".txt","r",encoding="utf-8") as f:
                   tmpList = f.readlines()
                   tmpStr = ",".join(tmpList)
                   tmpStr = tmpStr.replace("\n","")
                   tmpList = tmpStr.split(",")
                   if str(port) in tmpList:
                       continue
            with open("./resultIP/" + str(ip) + ".txt","a",encoding="utf-8") as f:
               f.write(str(port)+"\n")
def get_port_filename(dir1="./resultPort"):
    '''
    获取masscan扫描后的存储在resultPort目录下的所有文件名，提取为portlist
    '''
    portFileNameList = []
    my_dir = Path(dir1)
    for fileOrDir in my_dir.iterdir():
        if fileOrDir.is_file():
            portFileNameList.append(fileOrDir.stem)
    return portFileNameList.copy()
def single_thread_masscan_scan(port,ipList):
    count = masscan_one_port(port=port,ipList=ipList)
    ipWithPortList = get_ip_port_list(count=count,port=str(port))
    if (len(ipWithPortList)) == 0:
        return
    check_dir_is_exist_or_create(dir1="./resultPort")
    check_dir_is_exist_or_create(dir1="./resultIP")
    check_dir_is_exist_or_create(dir1="./tmpPortDir")
    # sort by port
    sort_and_store_masscan_res(type="port",port=port,ipWithPortList=ipWithPortList)
    # sort by IP
    sort_and_store_masscan_res(type="ip",port=port,ipWithPortList=ipWithPortList)

def nmap_one_port(port,ipList):
    tmpList = ipList.copy()
    count = 0
    while len(tmpList) > 0:
        count += 1
        ipScanList = []
        if len(tmpList) >= config.nmapScanLimit:
            for i in range(0,config.nmapScanLimit):
                ipScanList.append(tmpList.pop())
        else:
            ipScanList = tmpList.copy()
            tmpList = []
        ipScanStr = " ".join(ipScanList)
        check_dir_is_exist_or_create(dir1="./metaNmapResult")
        #nmapScanStr = "nmap -p" + str(port) + " -sT -sV -Pn -n --open " + ipScanStr +" -oA ./metaNmapResult/" + str(port) + "_" + str(count)
        nmapScanStr = "nmap -p" + str(port) + " -sT -sV -Pn -n --open " + ipScanStr +" -oA ./metaNmapResult/" + str(port) + "_" + str(count) + " 2>&1 1>/dev/null"
        print("[+] port: {} ,ip: {}".format(port,ipScanStr))
        child = subprocess.Popen(args=nmapScanStr,shell=True)
        child.wait()
    return count
def sort_and_store_nmap_info(file1):
    conn = sqlite3.connect(config.serverPortDBName)
    tree = ET.parse(file1)
    root = tree.getroot()
    hosts = root.findall("host")
    for host in hosts:
        ip = host.find("address").attrib['addr']
        ports = host.find("ports").findall("port")
        for port in ports:
            portID = port.attrib['portid']
            serviceName = port.find("service").attrib['name'] if "name" in port.find("service").attrib else "Null"
            productName = port.find("service").attrib['product'] if "product" in port.find("service").attrib else "Null"
            productVersion = port.find("service").attrib['version'] if "version" in port.find("service").attrib else "Null"
            #print("{} {} {} {} {}".format(ip,portID,serviceName,productName,productVersion))
            metaStr = ip+portID+serviceName+productName+productVersion
            h1=hashlib.md5()
            h1.update(metaStr.encode("utf-8"))
            sql = "INSERT OR IGNORE INTO portInfoDB VALUES('{}','{}','{}','{}','{}','{}')".format(h1.hexdigest(),ip,portID,serviceName,productName,productVersion)
            conn.execute(sql)
        conn.commit()
    conn.close()

def single_thread_nmap_scan(port):
    fileName = "./tmpPortDir/" + str(port) + ".txt"
    tmpList = []
    with open(fileName,"r",encoding="utf-8") as f:
        tmpList = f.readlines()
    my_file = Path(fileName)
    print("delete file")
    if my_file.exists():
        print("deleting{}".format(fileName))
        os.remove(fileName)
    tmpListStr = ",".join(tmpList)
    tmpListStr = tmpListStr.replace("\n","")
    tmpList = tmpListStr.split(",")
    ipInPortList = set_iplist(type="list",iplist=tmpList)
    count = nmap_one_port(port=port,ipList=ipInPortList)
    for i in range(1,count+1):
        fileName = "./metaNmapResult/" + str(port) + "_" + str(i)+ ".xml"
        if Path(fileName).exists():
            sort_and_store_nmap_info(file1=fileName)

def nmap_scan(masscanDoneFlag,dbname=config.serverPortDBName):
    conn = sqlite3.connect(dbname)
    sql = """
        CREATE TABLE IF NOT EXISTS portInfoDB (
        hash TEXT UNIQUE,
        ip TEXT,
        portID INTEGER,
        serviceName TEXT,
        productName TEXT,
        version TEXT
        )
    """
    conn.execute(sql)
    conn.commit()
    conn.close()
    count = 0
    print("nmap_scan")
    while True and (masscanDoneFlag.value == 1): 
        count += 1
        print("++++++++++{}+++++++".format(count))
        print("@@@@@@@@@@@@@@@@masscanDoneFlag.value={}".format(masscanDoneFlag.value))
        print("========================================namp scan =================")
        portFileNameList = []
        if Path("./tmpPortDir").exists():
            portFileNameList = get_port_filename(dir1="./tmpPortDir")
        if len(portFileNameList) == 0:
            time.sleep(5)
            continue
        print("|||||||||{}".format(portFileNameList))
        # for i in range(0,len(portFileNameList)):
        i = 0
        while i < len(portFileNameList):
            print("----------------------{}------".format(i))
            print("masscanDoneFlag.value={}".format(masscanDoneFlag.value))
            tmpThreadCount = config.ThreadCount if len(portFileNameList)-i >= config.ThreadCount else len(portFileNameList)-i
            threads = []
            for j in range(1,tmpThreadCount+1):
                t = NmapThread(single_thread_nmap_scan,(portFileNameList[i+j-1],j),str(j))
                threads.append(t)
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            i = i + tmpThreadCount

def export_to_excel(dbname=config.serverPortDBName):
    conn = sqlite3.connect(dbname)
    con = conn.cursor()
    sql = "select ip,portID,serviceName,productName,version from portInfoDB " #limit 10"
    wb = Workbook()
    sheet = wb.active
    #sheet = wb.create_sheet(0)
    title = ['id','IP','portID','serviceName','productName','version']
    #for row in con.execute(sql):
    #    print(type(row))
    con.execute(sql)
    rowList =  con.fetchall()
    for i in range(1,len(title)+1):
        sheet[chr(64+i)+str(1)]=title[i-1]
    for rowNum in range(1,len(rowList)+1):
        sheet[chr(65)+str(rowNum+1)]=rowNum
        for i in range(2,len(title)+1):
            sheet[chr(65+i-1) + str(rowNum + 1)]=rowList[rowNum-1][i-2]
    wb.save('test.xlsx')
def scanMain(ipGetType="file",iplist=[],portGetType="all",start=445,end=446,portList=[]):
    ipList = set_iplist(type=ipGetType,iplist=iplist)
    portList = list(set_portlist(scanType=portGetType,start=445,end=446,portList=portList))
    print(ipList)
    print(portList)
    masscanDoneFlag = multiprocessing.Value('i',1)
    # for port in portList:
    flag = True
    # for i in range(0,len(portList)):
    i = 0
    while i < len(portList):
        threads = []
        tmpThreadCount = config.ThreadCount if (len(portList)-i) >= config.ThreadCount else len(portList) - i 
        for j in range(1,tmpThreadCount+1):
            t = MasscanThread(single_thread_masscan_scan,(portList[i+j-1],j,ipList,),str(j))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        i = i + tmpThreadCount
        # start nmap scan
        if flag:
            flag = False
            p = multiprocessing.Process(target=nmap_scan,args=(masscanDoneFlag,config.serverPortDBName,))
            p.start()
        time.sleep(0.5)
    masscanDoneFlag.value = 0
    p.join()
    p.terminate()

    
def main(scan_type="all",isRestore=False,ipGetType="list",iplist=[],portGetType="all",start=445,end=446,portList=[]):
    #scan_type = 'nmap'
    #scan_type = 'stop'
    scan_type = 'all'
    if scan_type == "all":
        isRestore = False
        if not isRestore:
            tmp_dir1 = Path("./resultPort")
            tmp_dir2 = Path("./resultIP")
            tmp_dir3 = Path("./metaNmapResult")
            tmp_dir4 = Path("./bak")
            if not tmp_dir4.exists():
                tmp_dir4.mkdir()
            if tmp_dir1.exists():
                # child = subprocess.Popen(args="rm -rf ./resultPort",shell=True)
                cmd="mv -f ./resultPort ./bak/resultPort_$(date +%Y%m%d%H%M%S)_bak"
                child = subprocess.Popen(args=cmd,shell=True)
                child.wait()
            if tmp_dir2.exists():
                # child = subprocess.Popen(args="rm -rf ./resultIP",shell=True)
                cmd="mv -f ./resultIP ./bak/resultIP_$(date +%Y%m%d%H%M%S)_bak"
                child = subprocess.Popen(args=cmd,shell=True)
                child.wait()
            if tmp_dir3.exists():
                #child = subprocess.Popen(args="rm -rf ./metaNmapResult",shell=True)
                cmd="mv -f ./metaNmapResult ./bak/metaNmapResult_$(date +%Y%m%d%H%M%S)_bak"
                child = subprocess.Popen(args=cmd,shell=True)
                child.wait()
        else:
            pass
        # main(ipGetType="file",portGetType="All")
        scanMain(ipGetType=ipGetType,iplist=iplist,portGetType=portGetType,start=start,end=end,portList=portList)
    elif scan_type == "nmap":
        tmp_dir3 = Path("./metaNmapResult")
        # if tmp_dir3.exists():
        #     child = subprocess.Popen(args="rm -rf ./metaNmapResult",shell=True)
        #     child.wait()
        print("start")
        masscanDoneFlag = multiprocessing.Value("i",1)
        p=multiprocessing.Process(target=nmap_scan,args=(masscanDoneFlag,config.serverPortDBName,))
        p.start()
        time.sleep(0.5)
        masscanDoneFlag.value = 0
        p.join()
        p.terminate()
        print("end")
    export_to_excel()

if __name__ == '__main__':
    # main()
    main(scan_type="all",isRestore=False,ipGetType="list",iplist=['192.168.0.0/24'],portGetType="list",start=445,end=446,portList=[445])
