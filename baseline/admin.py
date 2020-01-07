from django.contrib import admin
from baseline import models

# Register your models here.
admin.site.register(models.LinuxScanRes)
admin.site.register(models.LinuxScanResMeta)
admin.site.register(models.WindowsScanRes)
admin.site.register(models.WindowsScanResMeta)