# Generated by Django 5.0.2 on 2024-04-14 12:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pcap_file',
            name='pfile',
            field=models.FileField(upload_to='uploads/'),
        ),
    ]
