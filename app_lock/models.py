from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Modelo de Times
class Team(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

# Modelo de Perfil (admin ou padrão)
class Profile(models.Model):
    ADMIN = 'admin'
    STANDARD = 'standard'
    PROFILE_CHOICES = [
        (ADMIN, 'Administrador'),
        (STANDARD, 'Padrão'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_type = models.CharField(max_length=10, choices=PROFILE_CHOICES, default=STANDARD)

    def __str__(self):
        return f"{self.user.username} ({self.get_profile_type_display()})"

# Modelo de vínculo do usuário com o time
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} ({self.team.name if self.team else 'Sem Time'})"

# Modelo de Serviço (relacionado ao criador e ao time dele)
class Service(models.Model):
    id = models.AutoField(primary_key=True)
    service_name = models.TextField(max_length=255)
    user_name = models.TextField(max_length=255)
    password = models.TextField(max_length=255)
    create_date = models.DateTimeField(default=timezone.now)
    update_date = models.DateTimeField(default=timezone.now)
    team = models.ForeignKey(Team, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.service_name} ({self.user_name})"
