from ldap3 import Server, Connection, ALL, SIMPLE
import ssl
import getpass

def autenticar_ldap():
    # Configurações - ajuste conforme necessário
    SERVIDOR = "ldap://cl.df.gov.br"
    USER_DN = "CN=Fábio Virgílio de Souza Neves,OU=Users,OU=seinf,OU=cldf,DC=cl,DC=df,DC=gov,DC=br"
    
    try:
        # 1. Verificação básica de conectividade
        print("🔍 Verificando conectividade com o servidor LDAP...")
        server = Server(SERVIDOR, get_info=ALL, connect_timeout=10)
        
        # 2. Tentativa de conexão anônima para verificar se o servidor está respondendo
        try:
            with Connection(server) as conn_anon:
                if conn_anon.bind():
                    print("ℹ️ Servidor responde a conexões anônimas")
                    print(f"Informações do servidor: {server.info}")
                else:
                    print("⚠️ Servidor não permite bind anônimo (comportamento esperado)")
        except Exception as e:
            print(f"⚠️ Não foi possível conectar ao servidor: {str(e)}")
            print("➡️ Verifique:")
            print("- O nome do servidor está correto")
            print("- Você está na rede correta")
            print("- O firewall permite conexões na porta 389 (LDAP)")
            return False

        # 3. Autenticação com credenciais
        print("\n🔑 Tentando autenticação...")
        senha = getpass.getpass(f"Digite a senha para {USER_DN}: ")
        
        with Connection(server,
                      user=USER_DN,
                      password=senha,
                      authentication=SIMPLE,
                      auto_bind=True) as conn:
            
            if conn.bound:
                print("✅ Autenticação bem-sucedida!")
                return True
            else:
                print("❌ Falha na autenticação")
                return False
                
    except Exception as e:
        print(f"🔥 Erro durante a autenticação: {str(e)}")
        
        # Diagnóstico avançado
        if "invalidCredentials" in str(e):
            print("➡️ Motivo: Credenciais inválidas (usuário ou senha incorretos)")
        elif "strongerAuthRequired" in str(e):
            print("➡️ Motivo: O servidor requer LDAPS (SSL/TLS)")
            print("Tente usar ldaps://cl.df.gov.br:636")
        elif "socket error" in str(e):
            print("➡️ Motivo: Problema de conexão com o servidor")
        else:
            print("➡️ Motivo: Desconhecido - verifique logs do servidor LDAP")
        
        return False

if __name__ == "__main__":
    print("=== Sistema de Autenticação LDAP ===")
    if autenticar_ldap():
        print("\nAcesso concedido!")
    else:
        print("\nAcesso negado. Recomendações:")
        print("1. Verifique seu nome de usuário e senha")
        print("2. Tente novamente mais tarde")
        print("3. Contate o administrador do sistema")
        print("4. Se necessário, teste com LDAPS (porta 636)")