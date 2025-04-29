from django import forms

class CadastroForm(forms.Form):
    service_name = forms.CharField(label='Nome do Serviço', max_length=100)
    user_name = forms.CharField(label='Nome do Usuário', max_length=100)
    password = forms.CharField(label='Senha', widget=forms.PasswordInput)
