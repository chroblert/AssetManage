from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class Owner(models.Model):
    OwnerName = models.CharField(max_length=30,verbose_name='Owner_Name')
    OwnerNum = models.CharField(max_length=7,verbose_name="Owner_Num")
    # OwnerID = models.IntegerField(verbose_name="Owner序列号")

    def __str__(self):
        return '%s' % self.OwnerName
    class Meta:
        verbose_name = '负责人'
        verbose_name_plural = "负责人"
class OSType(models.Model):
    os_type_choice = (
        ('Windows','Windows'),
        ('Linux','Linux'),
    )
    OSType = models.CharField(choices=os_type_choice,max_length=20,default="Linux",verbose_name="操作系统类型")
    OSVersion = models.CharField(max_length=64,unique=True,null=True,blank=True,verbose_name="操作系统版本")
    # OSTID = models.IntegerField(verbose_name="操作系统类型序列号")

    def __str__(self):
        return '%s' % self.OSType
    class Meta:
        verbose_name = '操作系统类型'
        verbose_name_plural = "操作系统类型"

class Service(models.Model):
    ServiceName = models.CharField(max_length=64,verbose_name="服务名称")
    # SCID = models.IntegerField(verbose_name="服务序列号")

    def __str__(self):
        return '%s' % self.ServiceName
    class Meta:
        verbose_name = '服务列表'
        verbose_name_plural = "服务列表"

class Port(models.Model):
    PortNum = models.IntegerField(verbose_name="端口号")
    # PID = models.IntegerField(verbose_name="端口序列号")

    def __str__(self):
        return '%s' % self.PortNum
    class Meta:
        verbose_name = '端口列表'
        verbose_name_plural = "端口列表"

class CSP(models.Model):
    csp_type_choice = (
        ('AliCloud','阿里云'),
        ('AWS','亚马逊云'),
        ('Azure','微软云')
    )
    csp_type = models.CharField(choices=csp_type_choice,max_length=20,default='aliCloud',verbose_name="云服务供应商")
    def __str__(self):
        return '%s' % self.csp_type
    class Meta:
        verbose_name = '云服务供应商'
        verbose_name_plural = '云服务供应商'
class Server(models.Model):
    ServerName = models.CharField(null=True,blank=True,max_length=64,verbose_name="服务器名称")
    PublicIP = models.GenericIPAddressField(protocol='IPv4',null=True,blank=True,verbose_name="公网IPV4地址")
    PrivateIP = models.GenericIPAddressField(protocol='IPv4',null=True,blank=True,verbose_name="私网IPV4地址")
    OwnerID = models.ForeignKey('Owner',verbose_name="负责人",null=True,on_delete=models.SET_NULL)
    OSTID = models.ForeignKey('OSType',verbose_name="操作系统类型",null=True,on_delete=models.SET_NULL)
    CSPID = models.ForeignKey('CSP',verbose_name="云服务供应商",null=True,on_delete=models.SET_NULL)

    def __str__(self):
        return '%s' % self.ServerName
    class Meta:
        verbose_name = "服务器列表"
        verbose_name_plural = "服务器列表"

class ServerPort(models.Model):
    SID = models.ForeignKey('Server',verbose_name="Server",null=True,on_delete=models.SET_NULL)
    PID = models.ForeignKey('Port',verbose_name="端口",null=True,blank=True,on_delete=models.SET_NULL)
    SCID = models.ForeignKey('Service',verbose_name="Service",null=True,on_delete=models.SET_NULL)

    def __str__(self):
        return '%s %s' % (Server.objects.get(id=self.SID_id),Port.objects.get(id=self.PID_id))
    class Meta:
        verbose_name = "服务器端口"
        verbose_name_plural = "服务器端口"
