# Generated by Django 5.0.6 on 2024-06-11 20:40

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app_lock', '0004_service_date'),
    ]

    operations = [
        migrations.RenameField(
            model_name='service',
            old_name='date',
            new_name='create_date',
        ),
        migrations.AddField(
            model_name='service',
            name='update_date',
            field=models.DateField(default=datetime.date.today),
        ),
    ]
