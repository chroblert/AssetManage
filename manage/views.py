from django.shortcuts import render
import xlrd
from assets import models
import xml.etree.ElementTree as ET
from django.core.exceptions import ObjectDoesNotExist
import copy
import datetime
import manage.portScan_MT
from multiprocessing import Process

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
    p = Process(target=port_scan)
    p.start()
    return render(request,'manage/result.html',locals())
def portscan_process(request):
    p = Process(target=port_scan)
    p.start()
    return render(request,'manage/result.html',locals())
def port_scan(data={}):
    scan_type="all"
    isRestore=False
    ipGetType="list"
    iplist=[]
    servers = models.ServerInfo.objects.all()
    for server in servers:
        if server.publicIP:
            iplist.append(server.publicIP)
    portGetType="list" # all
    start = 1
    end = 65535
    portList=[443]
    manage.portScan_MT.main(scan_type=scan_type,isRestore=isRestore,ipGetType=ipGetType,iplist=iplist,portGetType=portGetType,start=start,end=end,portList=portList)
    print("+++++++++++++++++++++++++++++OVER++++++++++++++++++++++++++")
