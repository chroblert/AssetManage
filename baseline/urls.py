from django.urls import path
from baseline import views

app_name = 'baseline'


urlpatterns = [
    # path('report/', views.report, name='report'),
    path('linux_scan_res_report/', views.linux_scan_res_report, name="linux_scan_res_report"),
    path('windows_scan_res_report/', views.windows_scan_res_report, name="windows_scan_res_report"),    
    path('scan_res_display/',views.scan_res_display,name="scan_res_display"),
    path('os_check_res_display/',views.os_check_res_display,name="os_check_res_display"),
    path('middlware_check_res_display/',views.middleware_check_res_display,name="middleware_check_res_display"),
    path('vuln_check_res_display/',views.vuln_check_res_display,name="vuln_check_res_display"),
    path('check_choice/',views.check_choice,name="check_choice"),
    path('test/',views.linux_vuln_check_res_store,name="test")
]