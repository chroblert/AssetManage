from django.shortcuts import render
import json
from CMDB import settings 
from django.views.decorators.csrf import csrf_exempt,csrf_protect
# Create your views here.
@csrf_exempt
def show(request):

    if request.method == "POST":
        bodyType=type(request.body)
        # = json.loads(request.body)
        bodyData=request.body
        settings.test= settings.test + json.dumps(json.loads(bodyData)) #str(bodyData)
        #settings.test= settings.test + str(bodyData) + "================================="
        test = settings.test
    else:
        settings.test = settings.test + "No"
        test = settings.test
    return render(request,'baseline/show.html',locals())