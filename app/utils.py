import base64

def generate_token(email: str, document: str) -> str:
    token_str = f"{email}:{document}"
    token_bytes = token_str.encode("utf-8")
    token = base64.b64encode(token_bytes).decode("utf-8")
    return "sdwork_" + token  

def parse_token(token: str):
    if not token.startswith("sdwork_"):
        return None
    token_data = token[len("sdwork_"):]
    try:
        decoded_bytes = base64.b64decode(token_data)
        decoded_str = decoded_bytes.decode("utf-8")
        email, document = decoded_str.split(":")
        return email, document
    except Exception:
        return None
