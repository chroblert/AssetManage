from django.urls import path
from manage import views


app_name = 'manage'


urlpatterns = [
    path('upload/',views.upload,name="upload"),
    path('display/',views.read_data_create,name="display"),
    path('portscan/',views.port_scan,name="portScan"),
    path('portcheck/',views.port_open_check,name="portCheck"),
    path("getlastportchecktime/",views.get_last_port_check_time,name="getLastPortCheckTime"),
]