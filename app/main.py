# app/main.py
from fastapi import FastAPI, HTTPException, status, Header, Request
from typing import Optional
from . import storage_sql as storage
from . import schemas
from .utils import generate_token, parse_token
from .rate_limiter import LoginRateLimiter

app = FastAPI(title="Microsserviço de Autenticação (Rate Limit - Login)")

API_PREFIX = "/api/v1/auth"

storage.init_db()

login_limiter = LoginRateLimiter(max_attempts=3, block_time=600)


def extract_sdwork_token(authorization: Optional[str]) -> Optional[str]:
    print("🔍 AUTH HEADER RECEBIDO:", authorization)
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "sdwork":
        return parts[1]
    if len(parts) == 1:
        return parts[0]
    return None


@app.post(f"{API_PREFIX}/signup", response_model=schemas.TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: schemas.SignupRequest):
    if storage.find_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email já cadastrado.")
    if storage.find_user_by_document(payload.document):
        raise HTTPException(status_code=400, detail="Documento já cadastrado.")

    user = storage.add_user(payload.name, payload.email, payload.document, payload.password)
    token = generate_token(user.email, user.document)
    return {"token": token}


@app.post(f"{API_PREFIX}/login", response_model=schemas.TokenResponse)
def login(payload: schemas.LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    ip_key = f"ip:{client_ip}"
    email_key = f"email:{payload.login.lower()}"

    if not login_limiter.check_allowed(ip_key):
        remaining = login_limiter.get_time_remaining(ip_key)
        raise HTTPException(status_code=429, detail=f"IP bloqueado. Tente novamente em {remaining} segundos.")

    if not login_limiter.check_allowed(email_key):
        remaining = login_limiter.get_time_remaining(email_key)
        raise HTTPException(status_code=429, detail=f"Email bloqueado. Tente novamente em {remaining} segundos.")

    user = storage.find_user_by_email(payload.login)
    if not user:
        login_limiter.register_failure(ip_key)
        login_limiter.register_failure(email_key)
        raise HTTPException(status_code=404, detail="Email não encontrado.")
    if user.password != payload.password:
        login_limiter.register_failure(ip_key)
        login_limiter.register_failure(email_key)
        raise HTTPException(status_code=401, detail="Senha incorreta.")

    login_limiter.reset(ip_key)
    login_limiter.reset(email_key)

    token = generate_token(user.email, user.document)
    return {"token": token}


@app.post(f"{API_PREFIX}/recuperar-senha", response_model=schemas.TokenResponse)
def recuperar_senha(payload: schemas.RecuperarSenhaRequest):
    user = storage.find_user_by_email_and_document(payload.email, payload.document)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    storage.update_password(payload.email, payload.document, payload.new_password)
    token = generate_token(payload.email, payload.document)
    return {"token": token}


@app.post(f"{API_PREFIX}/logout", response_model=schemas.MessageResponse)
def logout(authorization: Optional[str] = Header(None)):
    token = extract_sdwork_token(authorization)
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente ou inválido.")
    return {"message": "Logout efetuado com sucesso (token simbólico, sem expiração)."}


@app.get(f"{API_PREFIX}/me", response_model=schemas.UserResponse)
def me(authorization: Optional[str] = Header(None)):
    token = extract_sdwork_token(authorization)
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente ou inválido.")
    parsed = parse_token(token)
    if not parsed:
        raise HTTPException(status_code=400, detail="Token mal formatado.")
    email, document = parsed
    user = storage.find_user_by_email_and_document(email, document)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário não encontrado.")
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "document": user.document,
        "password": user.password
    }


@app.get("/")
def root():
    return {"service": "auth-microservice", "status": "Executando com limitador de taxa (bloqueio de 10 minutos após 3 tentativas de login falhas)"}
