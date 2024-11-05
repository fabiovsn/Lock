from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Service
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

@login_required
def home(request):
    try:
        if request.method == 'POST':
            form = CadastroForm(request.POST)
            if form.is_valid():
                service_name = form.cleaned_data['service_name']
                user_name = form.cleaned_data['user_name']
                password = form.cleaned_data['password']

                if Service.objects.filter(service_name=service_name).exists():
                    return JsonResponse({'error': 'Nome do serviço já existe'}, status=400)

                encrypted_password = encrypt_data(password)
                new_service = Service(service_name=service_name, user_name=user_name, password=encrypted_password)
                new_service.save()

                return JsonResponse({
                    'id': new_service.id,
                    'create_date': new_service.create_date.strftime('%Y-%m-%d %H:%M'),
                    'update_date': new_service.update_date.strftime('%Y-%m-%d %H:%M'),
                    'service_name': new_service.service_name,
                    'user_name': new_service.user_name,
                    'password': new_service.password,
                })
            else:
                return JsonResponse({'error': 'Erro ao processar o formulário'}, status=400)
        else:
            search_query = request.GET.get('search')
            if search_query:
                services = Service.objects.filter(Q(service_name__icontains=search_query) | Q(user_name__icontains=search_query))
            else:
                services = Service.objects.all()

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

def login_view(request):
    try:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                login(request, user)
                return redirect('home')
            else:
                return render(request, 'services/login.html', {'error': 'Usuário ou senha incorretos'})
        return render(request, 'services/login.html')
    except Exception as e:
        logger.error(f'Erro na função login_view: {e}')
        return JsonResponse({'error': 'Erro inesperado no servidor'}, status=500)

def logout_view(request):
    try:
        logout(request)
        return redirect('login')
    except Exception as e:
        logger.error(f'Erro na função logout_view: {e}')
        return JsonResponse({'error': 'Erro inesperado'}, status=500)

def export_csv(request):
    try:
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="export_data.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Id', 'Data de Criacao', 'Ultima Alteracao', 'Nome do Servico', 'Nome do Usuario', 'Senha'])

        local_tz = pytz.timezone('America/Sao_Paulo')

        for item in Service.objects.all():
            create_date_local = item.create_date.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S') if item.create_date else ''
            update_date_local = item.update_date.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S') if item.update_date else ''

            writer.writerow([
                item.id,
                create_date_local,
                update_date_local,
                item.service_name,
                item.user_name,
                decrypt_data(item.password)
            ])

        return response
    except Exception as e:
        logger.error(f'Erro na função export_csv: {e}')
        return JsonResponse({'error': 'Erro inesperado ao exportar CSV'}, status=500)
