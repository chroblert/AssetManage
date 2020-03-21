#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#https://github.com/vulmon
#https://github.com/ozelfatih
#https://vulmon.com

#==========================================================================
# LIBRARIES
#==========================================================================
from __future__ import print_function
import subprocess
import urllib
import json
import argparse
import platform
import sys
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

pV = sys.version_info[0]
if pV == 2:
    import urllib2
else:
    import requests

#==========================================================================
# GLOBAL VARIABLES
#==========================================================================
productList = []
queryData = ""
exploit_sum = 0
__version__ = 2.2

#==========================================================================
# FUNCTIONS
#==========================================================================
def args():
    global args

    description = "Host-based vulnerability scanner. Find installed packages on the host, ask their vulnerabilities to vulmon.com API and print vulnerabilities with available exploits. All found exploits can be downloaded by Vulmap."
    parser = argparse.ArgumentParser('vulmap.py', description=description)
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose mode', dest='verbose', required=False)
    parser.add_argument('-o', '--only-exploitablevulns', action='store_true', default=False, help='Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.', dest='onlyexploitable', required=False)
    parser.add_argument('-a', '--download-allexploits', action='store_true', default=False, help='Scans the computer and downloads all available exploits.', dest='exploit', required=False)
    parser.add_argument('-d', '--download-exploit', type=str, default=False, help='Downloads given exploit. ./%(prog)s -d EDB16372', dest='exploit_ID', required=False)
    parser.add_argument('-r', '--read-inventoryfile', type=str, default=False, nargs='?', const='inventory.json', help='Uses software inventory file rather than scanning local computer. ./%(prog)s -r pc0001.json', dest='InventoryOutFile', required=False)
    parser.add_argument('-s', '--save-inventoryfile', type=str, default=False, nargs='?', const='inventory.json', help='Saves software inventory file. Enabled automatically when Mode is CollectInventory. ./%(prog)s -r pc0001.json', dest='InventoryInFile', required=False)
    parser.add_argument('-c', '--collect-inventory', type=str, default=False, nargs='?', const='inventory.json', help='Collects software inventory but does not conduct a vulnerability scanning.Software inventory will be saved as inventory.json in default. ./%(prog)s -r pc0001.json', dest='CollectInventory', required=False)
    parser.add_argument('-p', '--proxy', type=str, default=False, help='Specifies a proxy server. Enter the URI of a network proxy server. ./%(prog)s -p localhost:8080', dest='proxy', required=False)
    parser.add_argument('-t', '--proxy-type', type=str, default=False, help='Specifies a proxy type ./%(prog)s -p https', dest='proxytype', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s version ' + str(__version__))
    args = parser.parse_args()

def underConstruction():
    print("This feature works with Python3")

def sendRequest(queryData,os="Linux",arc="x86_64"):
    product_list = '"product_list": ' + queryData

    json_request_data = '{'
    json_request_data += '"os": "' + os + '",'
    json_request_data += '"arc": "' + arc + '",'
    json_request_data += product_list
    json_request_data +=  '}'

    url = 'https://vulmon.com/scannerapi_vv211'
    body = 'querydata=' + json_request_data
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'cache-control': 'no-cache',
        'Pragma': 'no-cache'       
        }

    if args.proxy:
        if args.proxytype == 'https':
            proxy = args.proxy
            proxies = {'http' : 'https://'+proxy, 'https' : 'https://'+proxy}
            response = (requests.post(url, data=body, headers=headers, proxies=proxies, verify=False)).json()
        else:
            proxy = args.proxy
            proxies = {'http' : proxy, 'https' : proxy}
            response = (requests.post(url, data=body, headers=headers, proxies=proxies, verify=False)).json()
    else:
            response = requests.post(url, data=body, headers=headers)
            # print(response.content)
            if response.status_code == 200:
                response = response.json()
            else:
                response = {'status_message':'error'}

    return response

def outResults(q,os="Linux",arc="x86_64"):
    global exploit_sum

    queryData = q[:-1]
    queryData += ']'
    response = sendRequest(queryData,os=os,arc=arc)
    allProductExpList=[]
    if response['status_message'] == 'success':
        # 一个query_string
        for i in range(0, len(response["results"])):
            # allExpList=[]
            cveDictOfOneProduct={}
            tmpCVEList=[]
            # 查找到response['results'][i]['total_hits']个CVE
            for j in range(0, response['results'][i]['total_hits']):
                tmpCVEDict={}
                try:
                    if response['results'][i]['vulnerabilities'][j]['exploits']:
                        tmpCVEDict['CVEID']=response['results'][i]['vulnerabilities'][j]['cveid']
                        tmpCVEDict['CVEScore']=response['results'][i]['vulnerabilities'][j]['cvssv2_basescore']
                        # tmpCVEDict['product']=response['results'][i]['query_string']
                        print(bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Exploit Found!")
                        print(bcolors.OKGREEN + "[>] " + bcolors.ENDC + "Product: " + productFilter(response['results'][i]['query_string']))
                        tmpEXPList=[]
                        # 一个CVE有几个POC
                        for z in range(0, len(response['results'][i]['vulnerabilities'][j]['exploits'])):
                            exploit_sum += 1
                            edb = response['results'][i]['vulnerabilities'][j]['exploits'][z]['url'].split("=")
                            tmpDictInList={}
                            tmpDictInList['desc']=response['results'][i]['vulnerabilities'][j]['exploits'][z]['title']
                            tmpDictInList['edb']="EDB"+edb[2]
                            tmpEXPList.append(tmpDictInList)
                            print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + "Title: " + response['results'][i]['vulnerabilities'][j]['exploits'][z]['title'])
                            print(bcolors.FAIL + "[!] Exploit ID: EDB" + edb[2] + bcolors.ENDC + "\n")
                        tmpCVEDict['exp']=tmpEXPList
                        tmpCVEList.append(tmpCVEDict)
                except Exception as e:
                    continue

            if len(tmpCVEList) == 0:
                continue
            cveDictOfOneProduct['cve']=tmpCVEList
            cveDictOfOneProduct['product']=response['results'][i]['query_string']
            allProductExpList.append(cveDictOfOneProduct)
    else:
        pass
    print(allProductExpList)
    return allProductExpList

def getExploit(exploit_ID):
    url = 'https://vulmon.com/downloadexploit?qid=' + exploit_ID
    if pV == 2:
        urllib.urlretrieve(url, ("Exploit_" + exploit_ID))
    else:
        urllib.request.urlretrieve(url, ("Exploit_" + exploit_ID))
    if args.exploit_ID:
        print(bcolors.OKBLUE + "[Info] " + bcolors.ENDC + "Exploit Mode. Exploit downloading...\n")
        print(bcolors.OKGREEN + "[>] Filename: " + bcolors.ENDC + "Exploit_" + exploit_ID)
        print(bcolors.HEADER + "[Status] " + bcolors.ENDC + "Exploit Downloaded!\n" + bcolors.ENDC)

def vulnCheck(data=[],os="Linux",arc="x86_64"):
    # print("vulnCheck")
    count = 0
    # print("Reading software inventory from "+InventoryOutFile)
    # with open(InventoryOutFile) as json_file:
    #     products = json.load(json_file)
    productExpList=[]
    if len(data) == 0:
        return productExpList
    # print("in")
    products = data
    # print(products)
    
    for a in products:
        if count == 0:
            queryData = '['
        queryData += '{'
        queryData += '"product": "' + a[0] + '",'
        queryData += '"version": "' + a[1] + '",'
        queryData += '"arc": "' + a[2] + '"'
        queryData += '},'
        count += 1
        if count == 100:
            count = 0
            tmpList=outResults(queryData)
            productExpList.extend(tmpList)
    tmpList=outResults(queryData,os=os,arc=arc)
    productExpList.extend(tmpList)
    # productExpListStr=json.dumps(productExpList)
    print(productExpList)
    print("+++++++++++++++++++++++++++++++++++Over++++++++++++++++++++++++++++++++++")
    return productExpList

def productFilter(productName):
    productName = productName.replace('\\"', "")
    return(productName)


#==========================================================================
# CLASS
#==========================================================================
class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    HEADER = '\033[95m'
class args:
    proxy = None
    proxytype = "http"

#==========================================================================
# MAIN PROGRAM
#==========================================================================
if __name__ == '__main__':
    vulnCheck(data=[])