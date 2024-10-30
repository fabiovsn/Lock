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
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import csv
from django.http import HttpResponse
import pytz

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Chave de criptografia fixa
key = b'Fj7H0Bi25tBvG-iWD3eC2rQv4s9QL3k_kzq49AC7bKk='
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

@login_required  # Garante que só usuários logados podem acessar a home
def home(request):
    if request.method == 'POST':
        form = CadastroForm(request.POST)
        if form.is_valid():
            service_name = form.cleaned_data['service_name']
            user_name = form.cleaned_data['user_name']
            password = form.cleaned_data['password']

            # Verificação para ver se o nome do serviço já existe
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
            'user_name': request.user.username  # Passa o nome do usuário para o template
        })

def save_changes(request):
    if request.method == 'POST':
        service_id = request.POST.get('service_id')
        service = get_object_or_404(Service, id=service_id)
        new_service_name = request.POST.get('service_name')
        new_user_name = request.POST.get('user_name')
        password = request.POST.get('password')

        # Verificação para ver se o novo nome do serviço já existe (e é diferente do atual)
        if new_service_name != service.service_name and Service.objects.filter(service_name=new_service_name).exists():
            return JsonResponse({'error': 'Nome do serviço já existe'}, status=400)
        
        # Atualizar o nome do serviço
        service.service_name = new_service_name

        # Verificação para ver se o novo nome do usuário já existe (e é diferente do atual)
        if new_user_name != service.user_name and Service.objects.filter(user_name=new_user_name).exists():
            return JsonResponse({'error': 'Nome do usuário já existe'}, status=400)
        
        # Atualizar o nome do usuário
        service.user_name = new_user_name

        # Criptografar a nova senha apenas se ela for diferente da atual
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
            'password': decrypt_data(service.password)  # Enviar a senha descriptografada na resposta
        })
    else:
        return JsonResponse({'error': 'Método não permitido.'})

def delete_service(request, service_id):
    if request.method == 'POST':
        service = get_object_or_404(Service, id=service_id)
        service.delete()
        return JsonResponse({'success': True, 'message': 'Serviço excluído com sucesso.'})
    else:
        return JsonResponse({'success': False, 'message': 'Método não permitido.'})

def reveal_password(request, service_id):
    if request.method == 'POST':
        service = get_object_or_404(Service, id=service_id)
        try:
            decrypted_password = decrypt_data(service.password)
            return JsonResponse({'password': decrypted_password})
        except InvalidToken:
            logger.error(f'Erro ao descriptografar a senha do serviço {service.service_name}')
            return JsonResponse({'error': 'Erro ao descriptografar a senha'}, status=500)
        except Exception as e:
            logger.error(f'Erro inesperado: {e}')
            return JsonResponse({'error': 'Erro inesperado'}, status=500)
    else:
        return JsonResponse({'error': 'Método não permitido.'})
    

# Login


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('home')  # Redireciona para a página home
        else:
            return render(request, 'services/login.html', {'error': 'Usuário ou senha incorretos'})
    return render(request, 'services/login.html')

# @login_required  # Garante que só usuários logados podem acessar a home
# def home_view(request):
#     return render(request, 'services/home.html', {'user_name': request.user.username})

def logout_view(request):
    logout(request)  # Faz o logout do usuário
    return redirect('login')  # Redireciona para a página de login

def export_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="export_data.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Id', 'Data de Criacao', 'Ultima Alteracao', 'Nome do Servico', 'Nome do Usuario', 'Senha'])  # Cabeçalhos das colunas

    # Defina o fuso horário local que você deseja usar
    local_tz = pytz.timezone('America/Sao_Paulo')  # Ajuste conforme necessário

    for item in Service.objects.all():
        # Converta as datas para o fuso horário local
        create_date = item.create_date  # Data conforme está no banco de dados
        update_date = item.update_date
        
        # Converta as datas para o fuso horário local
        if create_date:
            create_date_local = create_date.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S')
        else:
            create_date_local = ''
        
        if update_date:
            update_date_local = update_date.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S')
        else:
            update_date_local = ''

        writer.writerow([
            item.id,
            create_date_local,
            update_date_local,
            item.service_name,
            item.user_name,
            decrypt_data(item.password)
        ])  # Dados dos itens

    return response