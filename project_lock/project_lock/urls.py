from django.urls import path
from app_lock import views
from django.contrib.auth import logout

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),  # Adicione esta linha
    path('', views.home, name='home'),  # URL padrão para a página inicial
    # path('edit_service/<int:service_id>/', views.edit_service, name='edit_service'),
    path('save_changes/', views.save_changes, name='save_changes'),
    path('delete_service/<int:service_id>/', views.delete_service, name='delete_service'),
    path('reveal_password/<int:service_id>/', views.reveal_password, name='reveal_password'),
    path('export-csv/', views.export_csv, name='export_csv'),
]

