from django.db import models

# Create your models here.
class LinuxScanRes(models.Model):
    publicIP=models.CharField(max_length=30,verbose_name="publicIP")
    privateIP=models.CharField(max_length=30,verbose_name="privateIP")
    hostname=models.CharField(max_length=30,verbose_name="hostname")
    osVersion=models.CharField(max_length=30,verbose_name="osVersion")
    kernelVersion=models.CharField(max_length=30,verbose_name="kernelVersion")

    tmpIfSeparate=models.BooleanField(default=False, verbose_name="tmpIfSeparate")
    tmpIfNoexec=models.BooleanField(default=False,verbose_name="tmpIfNoexec")
    tmpIfNosuid=models.BooleanField(default=False,verbose_name="tmpIfNosuid")

    grubcfgIfExist=models.BooleanField(default=True,verbose_name="grubcfgIfExist")
    grubcfgPermission=models.CharField(max_length="5",verbose_name="grubcfgPermission")
    grubcfgIfSetPasswd=models.BooleanField(default=False,verbose_name="grubcfgIfSetPasswd")
    singleUserModeIfNeedAuth=models.BooleanField(default=False,verbose_name="singleUserModeIfNeedAuth")
    selinuxState

    def __str__(self):
        return '%s' % "LinuxScanResult"