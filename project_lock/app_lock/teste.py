# from cryptography.fernet import Fernet, InvalidToken

# key = b'Fj7H0Bi25tBvG-iWD3eC2rQv4s9QL3k_kzq49AC7bKk='
# cipher_suite = Fernet(key)
# password = b'Z0FBQUFBQm1hZjY3a2VTTEp3OEtQdlNkMk9zTmFhRjFidmdvVGR0T1Y4c0RzcGVYQWtFdmwwUDZEOHBNWFFWN1pQMG9kY0V3TnZvNjdmZm9CUGp2dWpla3E2OFhoay13QkE9PQ=='

# try:
#     decrypted_password = cipher_suite.decrypt(password).decode('utf-8')
#     print(f"Senha descriptografada: {decrypted_password}")
# except InvalidToken:
#     print('Erro de token')

import base64
from cryptography.fernet import Fernet, InvalidToken
import logging

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


print(decrypt_data('Z0FBQUFBQm1iSnFkSjJraHFZN3BiS3ZVbWdwNUpoQmFkZ1BoM3Y1aHVwZ0QzaWZ1UkhkenBjQTVZSVhrS0x5MFhkQlJnd0JsOHAxNXVjWXBrd3pQOVJMYkttSFVpQXlXR2c9PQ=='))