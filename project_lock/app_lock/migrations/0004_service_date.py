# Generated by Django 5.0.6 on 2024-06-07 20:42

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app_lock', '0003_service_delete_usuario'),
    ]

    operations = [
        migrations.AddField(
            model_name='service',
            name='date',
            field=models.DateField(default=datetime.date.today),
        ),
    ]
