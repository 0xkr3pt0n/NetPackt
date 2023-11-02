from django.db import models
# from django.contrib.auth.models import User
# # Create your models here.
# class scan(models.Model):
#     # Fields for the first table
#     scan_date = models.DateField(auto_now_add=True)
#     system_ip = models.TextField()
#     shared_with = models.TextField(User, on_delete=models.CASCADE)
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     scan_name = models.TextField()
# class findings(models.Model):
#     scan_id = models.ForeignKey(scan, on_delete=models.CASCADE)
#     cve_id = models.ForeignKey('vulnerabilities', on_delete=models.CASCADE)
