from django.db import models

# Create your models here.
class pcap_file(models.Model):
    pfile = models.FileField(upload_to='uploads/')