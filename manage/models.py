from django.db import models

# Create your models here.

class File(models.Model):
    fileContent = models.FileField()
    # filteContent = models.CharField()
