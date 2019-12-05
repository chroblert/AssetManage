from django.shortcuts import render
import xlrd
from assets import models
import xml.etree.ElementTree as ET
import copy
import datetime

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
                OwnerID_id = models.Owner.objects.get_or_create(OwnerName=rowValues[5])[0].id
                OSVersion = rowValues[6]
                if not OSVersion:
                    OSType = ''
                else:
                    OSType = 'Windows' if ('Windows' in OSVersion) or ('windows' in OSVersion) else "Linux"
                OSTID_id = models.OSType.objects.get_or_create(OSType=OSType,OSVersion=OSVersion)[0].id
                CSPID_id = models.CSP.objects.get_or_create(csp_type=rowValues[1])[0].id
                PublicIP =  None if not rowValues[3] else rowValues[3]
                PrivateIP = None if not rowValues[4] else rowValues[4]
                ServerName = None if not rowValues[2] else rowValues[2]
                models.Server.objects.get_or_create( OwnerID_id=OwnerID_id,OSTID_id=OSTID_id,CSPID_id=CSPID_id,PublicIP=PublicIP,PrivateIP=PrivateIP,ServerName=ServerName)
                all_value_list.append(rowValues)
    return render(request,'manage/display.html',locals())

def read_port_create(request):
    if request.method == "POST":
        f = request.FILES['xml_file']
        type_xml = f.name.split('.')[1]
        if 'xml' == type_xml:
            tree = ET.parse(source=f.read())
            root = tree.getroot()
            hosts = root.findall("host")
            portList = []
            for host in hosts:

            pass
    return render(request,'manage/display_port.html',locals())

