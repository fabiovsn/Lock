from django.contrib import admin
from .models import Service, Team, UserProfile
from .views import decrypt_data  # Importa sua função de descriptografia

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ('id', 'service_name', 'user_name', 'team', 'decrypted_password', 'create_date', 'update_date')
    list_filter = ('team',)
    search_fields = ('service_name', 'user_name')

    def decrypted_password(self, obj):
        request = self.request_context
        if request and request.user.is_superuser:
            try:
                return decrypt_data(obj.password)
            except Exception:
                return 'Erro ao descriptografar'
        return 'Acesso negado'

    decrypted_password.short_description = 'Senha Descriptografada'

    # Precisamos capturar o request para saber quem é o usuário
    def get_queryset(self, request):
        self.request_context = request
        return super().get_queryset(request)

@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'team')
    list_filter = ('team',)
    search_fields = ('user__username', 'team__name')
