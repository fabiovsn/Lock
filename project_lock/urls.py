# from django.urls import path
# from app_lock import views
# from django.contrib.auth import logout

# urlpatterns = [
#     path('login/', views.login_view, name='login'),
#     path('logout/', views.logout_view, name='logout'),
#     path('', views.home, name='home'),  # URL padrão para a página inicial
#     path('save_changes/', views.save_changes, name='save_changes'),
#     path('delete_service/<int:service_id>/', views.delete_service, name='delete_service'),
#     path('reveal_password/<int:service_id>/', views.reveal_password, name='reveal_password'),
#     path('export-csv/', views.export_csv, name='export_csv'),
# ]

from django.urls import path, include
from django.contrib import admin  # <-- Importar o admin
from app_lock import views
from app_lock.views import ldap_authenticate_view

urlpatterns = [
    path('admin/', admin.site.urls),  # <-- Adicionar essa linha para liberar o Admin
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.home, name='home'),  # URL padrão para a página inicial
    path('save_changes/', views.save_changes, name='save_changes'),
    path('delete_service/<int:service_id>/', views.delete_service, name='delete_service'),
    path('reveal_password/<int:service_id>/', views.reveal_password, name='reveal_password'),
    path('export-csv/', views.export_csv, name='export_csv'),
    path('ldap-auth/', ldap_authenticate_view, name='ldap_authenticate'),
]