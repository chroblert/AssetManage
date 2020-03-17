from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class ServerInfo(models.Model):
    networkType=models.CharField(max_length=30,default="cloud",verbose_name="networkType")
    cloudServerProvider=models.CharField(max_length=30,blank=True,verbose_name="cloudServerProvider")
    serverName=models.CharField(max_length=100,null=True,blank=True,verbose_name="serverName")
    osVersion=models.CharField(max_length=100,null=True,blank=True,verbose_name="osVersion")
    publicIP = models.GenericIPAddressField(protocol='IPv4',null=True,blank=True,verbose_name="publicIP")
    privateIP = models.GenericIPAddressField(protocol='IPv4',null=True,blank=True,verbose_name="privateIP")
    owner = models.CharField(max_length=50,null=True,blank=True,verbose_name="owner")

    def __str__(self):
        return '%s %s'%(self.cloudServerProvider,self.serverName)
    class Meta:
        verbose_name="服务器信息"
        verbose_name_plural="服务器信息"
