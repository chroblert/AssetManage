from django.shortcuts import render
import xlrd
from assets import models
import xml.etree.ElementTree as ET
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt,csrf_protect
import copy
import datetime
import manage.portScan_MT
from multiprocessing import Process
import sqlite3
import manage.portOpenCheck
from django.http import HttpResponse
from pathlib import Path
import re

# Create your views here.

def index(request):

    return render(request,'manage/index.html',locals())
def upload(request):

    return render(request,'manage/upload.html',locals())
def read_data_create(request):
    if request.method == "POST":
        f = request.FILES['my_file']
        type_excel = f.name.split('.')[1]
        all_value_list = []
        if 'xlsx' == type_excel:
            row_value_list = []
            wb = xlrd.open_workbook(filename=None, file_contents=f.read())
            table = wb.sheets()[0]
            nrows = table.nrows # 行数
            for i in range(1,nrows):
                rowValues = table.row_values(i)
                CSP=rowValues[1]
                ServerName = None if not rowValues[2] else rowValues[2]
                PublicIP = None if not rowValues[3] else rowValues[3]
                PrivateIP = None if not rowValues[4] else rowValues[4]
                OwnerName=rowValues[5]
                OSVersion = rowValues[6]
                networkType="cloud" if CSP in ['AliCloud',"AWS","Azure"] else "private"
                models.ServerInfo.objects.get_or_create(networkType=networkType,cloudServerProvider=CSP,serverName=ServerName,osVersion=OSVersion,publicIP=PublicIP,privateIP=PrivateIP,owner=OwnerName)
                all_value_list.append(rowValues)
    # return render(request,'manage/display.html',locals())
    # 调用端口扫描工具进行扫描
    return render(request,'manage/result.html',locals())

def port_scan(request):
    print(type(request))
    print(request.POST)
    ipSource = request.POST['ipSource']
    portSource = request.POST['portSource']
    ipList = []
    if ipSource == "ipInDB":
        serverInfoList = models.ServerInfo.objects.all()
        for serverInfo in serverInfoList:
            if serverInfo.publicIP != None:
                ipList.append(serverInfo.publicIP)
    elif ipSource == "ipInText":
        ipText = request.POST['ipText']
        ipMetaList = ipText.split(",")
        for metaIP in ipMetaList:
            ipList.append(metaIP.strip())
    elif ipSource == "ipInFile":
        if not Path("./uploads").exists():
            Path("./uploads").mkdir()
        ipFile = request.FILES['ipFile']
        with open("./uploads/"+ipFile.name,"wb") as f:
            f.write(ipFile.read())
        with open("./uploads/"+ipFile.name,"r",encoding="utf-8") as f:
            ipList.extend(f.readlines())
    portList = []
    if portSource == "portInText":
        portText = request.POST['portText']
        portMetaList = portText.split(",")
        for metaPort in portMetaList:
            tmpPort = str(metaPort).strip()
            if tmpPort.isnumeric():
                portList.append(tmpPort)
            elif "-" in tmpPort:
                if len(tmpPort.split("-")) == 2 and tmpPort.split("-")[0].isnumeric() and tmpPort.split("-")[1].isnumeric() and int(tmpPort.split("-")[0]) <= int(tmpPort.split("-")[0]):
                    for tp in range(int(tmpPort.split("-")[0]),int(tmpPort.split("-")[1])+1):
                        portList.append(str(tp))
    elif portSource == "portInFile":
        if not Path("./uploads").exists():
            Path("./uploads").mkdir()
        portFile = request.FILES['portFile']
        with open("./uploads/"+portFile.name,"wb") as f:
            f.write(portFile.read())
        with open("./uploads/"+portFile.name,"r",encoding="utf-8") as f:
            portList.extend(f.readlines())
    
    # 线程数量
    tmpThreadCount=request.POST['threadCount']
    tmpMasscanScanIPLimit = request.POST['masscanScanIPLimit']
    tmpNmapScanIPLimit = request.POST['nmapScanIPLimit']
    manage.portScan_MT.config.setThreadCount(tmpThreadCount)
    manage.portScan_MT.config.setScanLimit(tmpMasscanScanIPLimit)
    manage.portScan_MT.config.setNmapScanLimit(tmpNmapScanIPLimit)
    data = {}
    data['iplist'] = ipList
    data['portList'] = portList
    # ipList.extend([tmpThreadCount,tmpMasscanScanIPLimit,tmpNmapScanIPLimit])
    if len(ipList) and len(portList):
        p = Process(target=port_scan_process,args=(data,))
        p.start()
        resStr = "ipSource : {}<br>portSource : {}<br>ipList :<br> {}<br>portList:<br>{}".format(ipSource,portSource,"<br>".join(ipList),"<br>".join(portList))
        return HttpResponse(resStr)
    return HttpResponse("Error")
def port_scan_process(data={}):
    scan_type="all"
    isRestore=False
    ipGetType="list"
    portGetType="list"
    iplist = data['iplist']
    portList = data['portList']
    manage.portScan_MT.main(scan_type=scan_type,isRestore=isRestore,ipGetType=ipGetType,iplist=iplist,portGetType=portGetType,portList=portList)
    print("+++++++++++++++++++++++++++++OVER++++++++++++++++++++++++++")
def port_open_check(request):
    timeStr = request.GET['time']
    with open("lastPortCheckTime.log",'w',encoding="utf-8") as f:
        f.write(timeStr)
    p = Process(target=port_open_check_process)
    p.start()
    p.join()
    return HttpResponse("Success")
def get_last_port_check_time(request):
    with open("lastPortCheckTime.log","r",encoding="utf-8") as f:
        timeStr=f.read()
    print(timeStr)
    return HttpResponse(timeStr)
def port_open_check_process():
    if not Path("portinfo.db").exists():
        print("[-] wrong")
        return
    conn = sqlite3.connect("portinfo.db")
    con = conn.cursor()
    sql = "select distinct(portID) from portInfoDB"
    con.execute(sql)
    resTupleList=con.fetchall()
    portList = []
    for r in resTupleList:
        portList.append(r[0])
    portIPDict = {}
    for port in portList:
        sql = "select distinct(ip) from portInfoDB where portID == {}".format(port)
        con.execute(sql)
        ipTupleList = con.fetchall()
        tmpIPList = []
        for r in ipTupleList:
            tmpIPList.append(r[0])
        portIPDict[port]=tmpIPList
    con.close()
    checkResList = manage.portOpenCheck.PortCheck(portIPDict).check()
    # 删除原来portInfoDB表中的记录
    conn = sqlite3.connect("portinfo.db")
    delSQL = "delete from portInfoDB"
    conn.execute(delSQL)
    conn.commit()
    # 将新记录插入portInfoDB表中
    for checkRes in checkResList:
        insertSQL = "INSERT OR IGNORE INTO portInfoDB VALUES('{}','{}','{}','{}','{}','{}')".format(checkRes['hashstr'],checkRes['ip'],checkRes['port'],checkRes['serviceName'],checkRes['productName'],checkRes['productVersion'])
        conn.execute(insertSQL)
        conn.commit()
    conn.close()
    print("[+] success")