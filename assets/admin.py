from django.contrib import admin
from assets import models
# Register your models here.
# from assets import asset_handler

admin.site.register(models.Owner)
admin.site.register(models.OSType)
admin.site.register(models.Service)
admin.site.register(models.Port)
admin.site.register(models.Server)
admin.site.register(models.ServerPort)
admin.site.register(models.CSP)