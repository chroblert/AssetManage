from django.urls import path
from baseline import views

app_name = 'baseline'


urlpatterns = [
    # path('report/', views.report, name='report'),
    path('linux_scan_res_report/', views.linux_scan_res_report, name="linux_scan_res_report"),
    path('windows_scan_res_report/', views.windows_scan_res_report, name="windows_scan_res_report"),    
    path('scan_res_display/',views.scan_res_display,name="scan_res_display"),
    path('check_res_display/',views.check_res_display,name="check_res_display"),
]