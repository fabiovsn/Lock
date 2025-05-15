from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .forms import CadastroForm
from django.forms.models import model_to_dict
from django.utils import timezone
from cryptography.fernet import Fernet, InvalidToken
import logging
import base64
from django.db.models import Q
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import csv
from django.http import HttpResponse
import pytz
from app_lock.encryption_key import key_b
from .models import Service, UserProfile, Team, User
from ldap3 import Server, Connection, ALL, NTLM
from .ldap_auth import autenticar_usuario
from django.conf import settings



# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Chave de criptografia fixa
key = key_b
cipher_suite = Fernet(key)

def encrypt_data(data):
    try:
        data_str = data
        data_bytes = data_str.encode('utf-8')
        encrypted_data = cipher_suite.encrypt(data_bytes)
        encrypted_data_base64 = base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        logger.debug(f'Data encrypted: {encrypted_data_base64}')
        return encrypted_data_base64
    except Exception as e:
        logger.error(f'Encryption error: {e}')
        raise


def decrypt_data(encrypted_data_base64):
    try:
        encrypted_data = base64.urlsafe_b64decode(encrypted_data_base64.encode('utf-8'))
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
        logger.debug(f'Data decrypted: {decrypted_data}')
        return decrypted_data
    except InvalidToken as e:
        logger.error(f'Decryption error: {e}, Data: {encrypted_data_base64}')
        raise
    except Exception as e:
        logger.error(f'Unexpected error during decryption: {e}')
        raise


def ldap_authenticate_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            return JsonResponse({'success': False, 'error': 'Usuário e senha são obrigatórios.'}, status=400)

        server_address = getattr(settings, 'LDAP_SERVER_URI', None)
        if not server_address:
            return JsonResponse({'success': False, 'error': 'LDAP_SERVER_URI não definido nas configurações.'}, status=500)

        if autenticar_usuario(username, password, server_address):
            return JsonResponse({'success': True, 'message': 'Autenticação bem-sucedida.'})
        else:
            return JsonResponse({'success': False, 'error': 'Falha na autenticação.'}, status=401)

    return JsonResponse({'error': 'Método não permitido.'}, status=405)


logger = logging.getLogger(__name__)


def login_view(request):
    try:
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')

            # Verifica se o usuário é superusuário (admin) e faz login localmente
            user = authenticate(request, username=username, password=password)
            if user and user.is_superuser:
                login(request, user)
                return redirect('home')

            # Caso contrário, tenta autenticar via Active Directory (LDAP)
            server_address = settings.LDAP_SERVER_URI
            if autenticar_usuario(username, password, server_address):
                user, created = User.objects.get_or_create(username=username)
                if created:
                    user.set_unusable_password()  # Definir senha inválida ao criar o usuário via LDAP
                    user.save()

                # Criar perfil se não existir
                try:
                    profile, profile_created = UserProfile.objects.get_or_create(user=user)
                    if profile_created:
                        if user.is_superuser:
                            profile.team = None  # O superusuário pode ficar sem time ou ser atribuído a um time específico
                        else:
                            default_team, _ = Team.objects.get_or_create(name='Sem Time')
                            profile.team = default_team
                        profile.save()
                except Exception as e:
                    logger.error(f"Erro ao criar UserProfile para {username}: {e}")

                login(request, user)
                return redirect('home')
            else:
                return render(request, 'services/login.html', {'error': 'Falha na autenticação do Active Directory'})

        return render(request, 'services/login.html')

    except Exception as e:
        logger.error(f'Erro na função login_view: {e}')
        return render(request, 'services/login.html', {'error': 'Erro inesperado no servidor'})


    

@login_required
def home(request):
    try:
        # Verifica ou cria o perfil do usuário
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)
        if not user_profile.team:
            default_team, _ = Team.objects.get_or_create(name='Sem Time')
            user_profile.team = default_team
            user_profile.save()

        user_team = user_profile.team

        if request.method == 'POST':
            form = CadastroForm(request.POST)
            if form.is_valid():
                service_name = form.cleaned_data['service_name']
                user_name = form.cleaned_data['user_name']
                password = form.cleaned_data['password']

                team = None if request.user.is_superuser else user_team

                if Service.objects.filter(service_name=service_name, team=team).exists():
                    return JsonResponse({'error': 'Nome do serviço já existe para este time'}, status=400)

                encrypted_password = encrypt_data(password)

                new_service = Service.objects.create(
                    service_name=service_name,
                    user_name=user_name,
                    password=encrypted_password,
                    create_date=timezone.now(),
                    update_date=timezone.now(),
                    team=team
                )

                return JsonResponse({
                    'id': new_service.id,
                    'create_date': new_service.create_date.strftime('%Y-%m-%d %H:%M'),
                    'update_date': new_service.update_date.strftime('%Y-%m-%d %H:%M'),
                    'service_name': new_service.service_name,
                    'user_name': new_service.user_name,
                    'password': decrypt_data(new_service.password),
                })
            else:
                return JsonResponse({'error': 'Erro ao processar o formulário'}, status=400)

        else:
            search_query = request.GET.get('search')
            team_filter = {} if request.user.is_superuser else {'team': user_team}

            if search_query:
                services = Service.objects.filter(
                    Q(service_name__icontains=search_query) |
                    Q(user_name__icontains=search_query),
                    **team_filter
                )
            else:
                services = Service.objects.filter(**team_filter)

            decrypted_services = []
            for service in services:
                decrypted_service = model_to_dict(service)
                try:
                    decrypted_service['password'] = decrypt_data(service.password)
                except InvalidToken:
                    logger.error(f'Erro ao descriptografar a senha do serviço {service.service_name}')
                    decrypted_service['password'] = 'Erro ao descriptografar'
                decrypted_services.append(decrypted_service)

            form = CadastroForm()
            return render(request, 'services/home.html', {
                'services': decrypted_services,
                'form': form,
                'user_name': request.user.username
            })

    except Exception as e:
        logger.error(f'Erro na função home: {e}')
        return JsonResponse({'error': 'Erro inesperado no servidor'}, status=500)


def save_changes(request):
    try:
        if request.method == 'POST':
            service_id = request.POST.get('service_id')
            service = get_object_or_404(Service, id=service_id)
            new_service_name = request.POST.get('service_name')
            new_user_name = request.POST.get('user_name')
            password = request.POST.get('password')

            if new_service_name != service.service_name and Service.objects.filter(service_name=new_service_name).exists():
                return JsonResponse({'error': 'Nome do serviço já existe'}, status=400)
            
            service.service_name = new_service_name

            if new_user_name != service.user_name and Service.objects.filter(user_name=new_user_name).exists():
                return JsonResponse({'error': 'Nome do usuário já existe'}, status=400)
            
            service.user_name = new_user_name

            if password != decrypt_data(service.password):
                encrypted_password = encrypt_data(password)
            else:
                encrypted_password = service.password

            service.password = encrypted_password
            service.update_date = timezone.now()
            service.save()

            return JsonResponse({
                'message': 'Alterações salvas com sucesso.',
                'update_date': service.update_date.astimezone(timezone.get_current_timezone()).strftime('%Y-%m-%d %H:%M'),
                'password': decrypt_data(service.password)
            })
        else:
            return JsonResponse({'error': 'Método não permitido.'})
    except Exception as e:
        logger.error(f'Erro na função save_changes: {e}')
        return JsonResponse({'error': 'Erro inesperado no servidor'}, status=500)

def delete_service(request, service_id):
    try:
        if request.method == 'POST':
            service = get_object_or_404(Service, id=service_id)
            service.delete()
            return JsonResponse({'success': True, 'message': 'Serviço excluído com sucesso.'})
        else:
            return JsonResponse({'success': False, 'message': 'Método não permitido.'})
    except Exception as e:
        logger.error(f'Erro na função delete_service: {e}')
        return JsonResponse({'error': 'Erro inesperado no servidor'}, status=500)

def reveal_password(request, service_id):
    try:
        if request.method == 'POST':
            service = get_object_or_404(Service, id=service_id)
            decrypted_password = decrypt_data(service.password)
            return JsonResponse({'password': decrypted_password})
        else:
            return JsonResponse({'error': 'Método não permitido.'})
    except InvalidToken:
        logger.error(f'Erro ao descriptografar a senha do serviço {service.service_name}')
        return JsonResponse({'error': 'Erro ao descriptografar a senha'}, status=500)
    except Exception as e:
        logger.error(f'Erro na função reveal_password: {e}')
        return JsonResponse({'error': 'Erro inesperado'}, status=500)


def logout_view(request):
    try:
        logout(request)
        return redirect('login')
    except Exception as e:
        logger.error(f'Erro na função logout_view: {e}')
        return JsonResponse({'error': 'Erro inesperado'}, status=500)


@login_required
def export_csv(request):
    try:
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="export_data.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['ID', 'DATA_CRIACAO', 'ULTIMA_ALTERACAO', 'NOME_SERVICO', 'NOME_USUARIO', 'SENHA', 'NOME_TIME'])

        local_tz = pytz.timezone('America/Sao_Paulo')

        if request.user.is_superuser:
            services = Service.objects.all()
        else:
            try:
                user_profile = UserProfile.objects.get(user=request.user)
                user_team = user_profile.team
                services = Service.objects.filter(team=user_team)
            except UserProfile.DoesNotExist:
                logger.error(f'Perfil de usuário não encontrado para {request.user.username}')
                return JsonResponse({'error': 'Usuário sem perfil definido. Contate o administrador.'}, status=403)

        for item in services:
            create_date_local = item.create_date.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S') if item.create_date else ''
            update_date_local = item.update_date.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S') if item.update_date else ''
            team_name = item.team.name if item.team else 'Sem Time'
            
            # Tenta descriptografar a senha com tratamento de erro
            try:
                decrypted_password = decrypt_data(item.password)
            except InvalidToken:
                logger.error(f'Erro ao descriptografar a senha do serviço {item.service_name}')
                decrypted_password = 'Erro ao descriptografar'

            writer.writerow([
                item.id,
                create_date_local,
                update_date_local,
                item.service_name,
                item.user_name,
                decrypted_password,
                team_name
        ])

        return response
    except Exception as e:
        logger.error(f'Erro na função export_csv: {e}')
        return JsonResponse({'error': 'Erro inesperado ao exportar CSV'}, status=500)
    

# def authenticate_ldap(username, password, domain, server_address):
#     try:
#         server = Server(server_address, get_info=ALL)
#         user_dn = f"CN={username},CN=Users,DC=cl,DC=df,DC=gov,DC=br"


#         connection = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)
        
#         # Verificar se a autenticação foi bem-sucedida
#         if connection.bind():
#             return True
#         else:
#             return False
#     except Exception as e:
#         logger.error(f'LDAP authentication failed: {e}')
#         return False

