from ldap3 import Server, Connection, ALL, NTLM

def autenticar_usuario(username, password):
    try:
        # Configura o servidor LDAP
        server = Server("ldap://cl.df.gov.br", get_info=ALL)
        user_dn = f"cl.df.gov.br\\{username}"  # Nome de usuário no formato DOMAIN\username
        print(f"Tentando autenticar com: user_dn={user_dn}")  # Log do DN sendo usado

        # Estabelece a conexão com autenticação NTLM
        connection = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

        print("✅ Autenticação bem-sucedida com NTLM!")
        return True

    except Exception as e:
        print(f"❌ Erro ao autenticar {username}: {e}")
        return False

if __name__ == "__main__":
    username = input("Digite o nome de usuário: ")
    password = input("Digite a senha: ")

    if autenticar_usuario(username, password):
        print("✅ Autenticação bem-sucedida!")
    else:
        print("❌ Falha na autenticação.")
