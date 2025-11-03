from cryptography.fernet import Fernet

SECRET_KEY = Fernet.generate_key()
fernet = Fernet(SECRET_KEY)

def generate_token(email: str, document: str) -> str:
    data = f"{email}:{document}".encode("utf-8")
    encrypted = fernet.encrypt(data)
    return "sdwork_" + encrypted.decode("utf-8")

def parse_token(token: str):
    if not token.startswith("sdwork_"):
        return None
    encrypted = token[len("sdwork_"):]
    try:
        decrypted = fernet.decrypt(encrypted.encode("utf-8"))
        email, document = decrypted.decode("utf-8").split(":")
        return email, document
    except Exception:
        return None
