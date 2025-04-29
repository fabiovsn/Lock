from ldap3 import Server, Connection, ALL, NTLM
import logging

logger = logging.getLogger(__name__)

def autenticar_usuario(username, password, server_address):
    try:
        server = Server(server_address, get_info=ALL)
        user_dn = f"cl.df.gov.br\\{username}"

        logger.info(f"Tentando autenticar com user_dn={user_dn}")

        connection = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=10
        )

        logger.info("✅ Autenticação NTLM bem-sucedida")
        return True

    except Exception as e:
        logger.warning(f"❌ Erro ao autenticar {username}: {e}")
        return False
