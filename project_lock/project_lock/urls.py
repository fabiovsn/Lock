from django.urls import path
from app_lock import views

urlpatterns = [
    path('', views.home, name='home'),  # URL padrão para a página inicial
    # path('edit_service/<int:service_id>/', views.edit_service, name='edit_service'),
    path('save_changes/', views.save_changes, name='save_changes'),
    path('delete_service/<int:service_id>/', views.delete_service, name='delete_service')
]
