from django.db import models
from django.utils import timezone

class Service(models.Model):
    id = models.AutoField(primary_key=True)
    service_name = models.TextField(max_length=255)
    user_name = models.TextField(max_length=255)
    password = models.TextField(max_length=255)
    create_date = models.DateTimeField(default=timezone.now)
    update_date = models.DateTimeField(default=timezone.now)

    # def save(self, *args, **kwargs):
    #     if Service.objects.filter(user_name=self.user_name).exists():
    #         pass
    #     else:
    #         super(Service, self).save(*args, **kwargs)

    # @staticmethod
    # def edit_service(service_id, service_name, user_name, password, update_date):
    #     service = Service.objects.get(id=service_id)
    #     service.service_name = service_name
    #     service.user_name = user_name
    #     service.password = password
    #     service.update_date = update_date
    #     service.save()
