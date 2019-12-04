from django.shortcuts import render
from django.shortcuts import HttpResponse
from django.views.decorators.csrf import csrf_exempt
# Create your views here.
import json
from assets import models
from assets import asset_handler
from django.shortcuts import get_object_or_404
from django.db.models import Count


def index(request):
    """
    资产总表视图
    :param request:
    :return:
    """
    servers = models.ServerS.objects.all()
    ports = models.Port.objects.all()
    server_detail_list = []
    for server in servers:
        port_list = []
        server_detail_dict = {}
        server_detail_dict['CSP'] = models.CSP.objects.get(id=server.CSPID_id).csp_type
        server_detail_dict['OSType'] = models.OSType.objects.get(id=server.OSTID_id).OSType
        server_detail_dict['ServerName'] = server.ServerName
        server_detail_dict['PublicIP'] = server.PublicIP
        server_detail_dict['PrivateIP'] = server.PrivateIP
        server_detail_dict['Owner'] = models.Owner.objects.get(id=server.OwnerID_id).OwnerName
        # 开始拼接端口
        # tmp = ''
        for port in models.ServerPort.objects.filter(SID_id=server.id):
            port_list.append(ports.get(id=port.PID_id))
        server_detail_dict['Ports'] = port_list
        server_detail_list.append(server_detail_dict)
    ostypes = models.OSType.objects.all()
    assets = models.Asset.objects.all()
    return render(request, 'assets/index.html', locals())


def dashboard(request):
    # total = models.Asset.objects.count()
    total = models.ServerS.objects.count()
    # upline = models.Asset.objects.filter(status=0).count()
    ali_count = models.ServerS.objects.filter(CSPID_id=1).count()
    azure_count = models.ServerS.objects.filter(CSPID_id=3).count()
    aws_count = models.ServerS.objects.filter(CSPID_id=2).count()
    # offline = models.Asset.objects.filter(status=1).count()
    # unknown = models.Asset.objects.filter(status=2).count()
    breakdown = models.Asset.objects.filter(status=3).count()
    backup = models.Asset.objects.filter(status=4).count()

    ali_rate =  round(ali_count/total*100) if total != 0 else 0
    azure_rate =  round(azure_count/total*100) if total != 0 else 0
    aws_rate =  round(aws_count/total*100) if total != 0 else 0
    # up_rate =  round(upline/total*100) if total != 0 else 0
    # o_rate =   round(offline / total * 100) if total != 0 else 0
    # un_rate =  round(unknown / total * 100) if total != 0 else 0
    bd_rate =  round(breakdown / total * 100) if total != 0 else 0
    bu_rate =  round(backup / total * 100) if total != 0 else 0

    # 端口分布图
    # 每个端口对应多少个Server
    # 取出占比前10的端口
    # 在ServerPort中按照PID_id进行分组，按照各个分组中的个数进行排序
    port_num_count_list = []
    port_count_sort = models.ServerPort.objects.values("PID_id").annotate(port_count=Count("PID_id")).order_by("-port_count")[:10]
    for port_dic in port_count_sort:
        port_num_count_dict = {}
        port_num = models.Port.objects.filter(id=port_dic['PID_id'])[0].PortNum
        port_count = port_dic['port_count']
        port_num_count_dict['port_count'] = port_count
        port_num_count_dict['port_num'] = port_num
        port_num_count_list.append(port_num_count_dict)
    server_number = models.Server.objects.count()
    networkdevice_number = models.NetworkDevice.objects.count()
    storagedevice_number = models.StorageDevice.objects.count()
    securitydevice_number = models.SecurityDevice.objects.count()
    software_number = models.Software.objects.count()

    return render(request, 'assets/dashboard.html', locals())


def detail(request, asset_id):
    """
    以显示服务器类型资产详细为例，安全设备、存储设备、网络设备等参照此例。
    :param request:
    :param asset_id:
    :return:
    """

    asset = get_object_or_404(models.Asset, id=asset_id)
    return render(request, 'assets/detail.html', locals())





@csrf_exempt
def report(request):
    if request.method == 'POST':
        asset_data = request.POST.get('asset_data')
        data = json.loads(asset_data)
        if not data:
            return HttpResponse('没有数据！')
        if not issubclass(dict, type(data)):
            return HttpResponse('数据必须为字典格式！')
        # 你的检测代码

        sn = data.get('sn', None)

        if sn:
            asset_obj = models.Asset.objects.filter(sn=sn)  # [obj]
            if asset_obj:
                update_asset = asset_handler.UpdateAsset(request, asset_obj[0], data)
                return HttpResponse('资产数据已经更新。')
            else:
                obj = asset_handler.NewAsset(request, data)
                response = obj.add_to_new_assets_zone()
                return HttpResponse(response)
        else:
            return HttpResponse('没有资产sn，请检查数据内容！')

    return HttpResponse('200 ok')
