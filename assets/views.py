from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.views.decorators.csrf import csrf_exempt
# Create your views here.
import json
from assets import models
from django.shortcuts import get_object_or_404
from django.db.models import Count
from django.core.exceptions import ObjectDoesNotExist
import sqlite3
import os
from pathlib import Path


def index(request):
    """
    资产总表视图
    :param request:
    :return:
    """
    server_detail_list = []
    servers=models.ServerInfo.objects.all()
    for server in servers:
        server_dict={}
        server_dict['CSP']=server.cloudServerProvider
        server_dict['serverName']=server.serverName
        server_dict['osVersion']=server.osVersion
        server_dict['publicIP']=server.publicIP
        server_dict['privateIP']=server.privateIP
        server_dict['owner']=server.owner
        server_detail_list.append(server_dict)
    return render(request, 'assets/index.html', locals())


def dashboard(request):
    # total = models.Server.objects.all().count()
    total = models.ServerInfo.objects.all().count()
    try:
        # ali_count = models.Server.objects.filter(CSPID_id=models.CSP.objects.get(csp_type="AliCloud").id).count()
        ali_count = models.ServerInfo.objects.filter(cloudServerProvider="AliCloud").count()
    except ObjectDoesNotExist:
        ali_count = 0
    try:
        # azure_count = models.Server.objects.filter(CSPID_id=models.CSP.objects.get(csp_type="Azure").id).count()
        azure_count = models.ServerInfo.objects.filter(cloudServerProvider="Azure").count()
    except ObjectDoesNotExist:
        azure_count = 0
    try:
        # aws_count = models.Server.objects.filter(CSPID_id=models.CSP.objects.get(csp_type="AWS").id).count()
        aws_count = models.ServerInfo.objects.filter(cloudServerProvider="AWS").count()
    except ObjectDoesNotExist:
        aws_count = 0
    breakdown = 0 #models.Asset.objects.filter(status=3).count()
    backup = 0 #models.Asset.objects.filter(status=4).count()

    ali_rate =  round(ali_count/total*100) if total != 0 else 0 
    azure_rate =  round(azure_count/total*100) if total != 0 else 0
    aws_rate =  round(aws_count/total*100) if total != 0 else 0
    bd_rate =  round(breakdown / total * 100) if total != 0 else 0
    bu_rate =  round(backup / total * 100) if total != 0 else 0

    # 端口分布图
    # 每个端口对应多少个Server
    # 取出占比前10的端口
    # 在ServerPort中按照PID_id进行分组，按照各个分组中的个数进行排序
    port_num_count_list = []
    port_num=0
    port_count=0
    dbfile="portinfo.db"
    if not Path(dbfile).exists():
        return render(request,'assets/dashboard.html',locals())
    conn = sqlite3.connect("portinfo.db")
    con = conn.cursor()
    sql = "select distinct(portID) from portInfoDB"
    con.execute(sql)
    portTupleList=con.fetchall()
    for portTuple in portTupleList:
        port_num_count_dict = {}
        port_num=portTuple[0]
        sql = "select count(*) from portInfoDB where portID = {}".format(port_num)
        con.execute(sql)
        portNumTupleList=con.fetchall()
        port_count = portNumTupleList[0][0]
        port_num_count_dict['port_count'] = port_count
        port_num_count_dict['port_num'] = port_num
        port_num_count_list.append(port_num_count_dict)
    con.close()
    return render(request, 'assets/dashboard.html', locals())

def displayport(request):
    dbfile="portinfo.db"
    if not Path(dbfile).exists():
        return render(request,'assets/serverPortInfo.html',locals())
    conn = sqlite3.connect("portinfo.db")
    con = conn.cursor()
    sql = "select * from portInfoDB"
    con.execute(sql)
    serverPortTupleList = con.fetchall()
    con.close()
    # print(serverPortDictList)
    # print(os.getcwd())
    serverPortDictList=[]
    for serverPortTuple in serverPortTupleList:
        # print(serverPortTuple)
        serverPortDict={}
        serverPortDict['ip']=serverPortTuple[1]
        serverPortDict['port']=serverPortTuple[2]
        serverPortDict['service']=serverPortTuple[3]
        serverPortDict['product']=serverPortTuple[4]
        serverPortDict['version']=serverPortTuple[5]
        serverPortDict['osVersion']=models.ServerInfo.objects.filter(publicIP=serverPortDict['ip'])[0].osVersion
        serverPortDict['serverName']=models.ServerInfo.objects.filter(publicIP=serverPortDict['ip'])[0].serverName
        serverPortDictList.append(serverPortDict)
    return render(request,'assets/serverPortInfo.html',locals())
