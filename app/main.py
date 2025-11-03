from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.security import APIKeyHeader
from typing import Optional
from . import storage_sql as storage
from . import schemas
from .utils import generate_token, parse_token
from . import cache_redis as cache_manager
import time

api_key_header = APIKeyHeader(name="Authorization", auto_error=False) #hastag so para ter mudança no codigo e poder subir pro git

app = FastAPI(
    title="Microsserviço de Autenticação (MS-Auth) com Rate Limit + Redis",
    version="2.0.0",
    description="API de autenticação com Redis, criptografia simétrica e validação segura.",
    swagger_ui_parameters={"persistAuthorization": True},
)

API_PREFIX = "/api/v1/auth"
storage.init_db()

THROTTLE_LIMIT = 5      
THROTTLE_TIME = 30        
RATE_LIMIT_ATTEMPTS = 3
RATE_LIMIT_BLOCK = 600

def get_token_header(authorization: Optional[str] = Depends(api_key_header)):
    return authorization

def extract_sdwork_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) == 2 and parts[0].lower() == "sdwork":
        return parts[1]
    if len(parts) == 1:
        return parts[0]
    return None

@app.get("/")
def root():
    return {
        "service": "auth-microservice",
        "status": "running with Redis and encryption"
    }

@app.post(f"{API_PREFIX}/signup", response_model=schemas.TokenResponse, status_code=201, tags=["Autenticação"])
def signup(payload: schemas.SignupRequest):
    if storage.find_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email já cadastrado.")
    if storage.find_user_by_document(payload.document):
        raise HTTPException(status_code=400, detail="Documento já cadastrado.")
    user = storage.add_user(payload.name, payload.email, payload.document, payload.password)
    token = generate_token(user.email, user.document)
    return {"token": token}

@app.post(f"{API_PREFIX}/login", response_model=schemas.TokenResponse, tags=["Autenticação"])
def login(payload: schemas.LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    key = f"login:{client_ip}"
    count = cache_manager.increment_key(key, RATE_LIMIT_BLOCK)

    if count > RATE_LIMIT_ATTEMPTS:
        ttl = int(cache_manager.r.ttl(key))
        raise HTTPException(status_code=429, detail=f"Bloqueado por tentativas excessivas. Espere {ttl}s.")

    user = storage.find_user_by_email(payload.login)
    if not user or user.password != payload.password:
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")

    token = generate_token(user.email, user.document)
    return {"token": token}

@app.post(f"{API_PREFIX}/recuperar-senha", tags=["Autenticação"])
def solicitar_token_recuperacao(payload: schemas.RecuperarSenhaRequest):
    user = storage.find_user_by_email_and_document(payload.email, payload.document)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    recovery_token = generate_token(payload.email, payload.document)
    cache_manager.set_temp_token(f"recovery:{payload.email}", recovery_token, ttl=300)
    return {"message": "Token de recuperação gerado. Válido por 5 minutos.", "token": recovery_token}

@app.post(f"{API_PREFIX}/confirmar-recuperacao", response_model=schemas.TokenResponse, tags=["Autenticação"])
def confirmar_recuperacao(payload: schemas.RecuperarSenhaRequest):
    token_salvo = cache_manager.get_temp_token(f"recovery:{payload.email}")
    if not token_salvo:
        raise HTTPException(status_code=400, detail="Token de recuperação expirado ou inválido.")
    storage.update_password(payload.email, payload.document, payload.new_password)
    token = generate_token(payload.email, payload.document)
    return {"token": token}

@app.get(f"{API_PREFIX}/me", response_model=schemas.UserResponse, tags=["Autenticação"])
def me(request: Request, authorization: Optional[str] = Depends(get_token_header)):
    client_ip = request.client.host
    key = f"throttle:{client_ip}:me"
    count = cache_manager.increment_key(key, THROTTLE_TIME)
    if count > THROTTLE_LIMIT:
        ttl = int(cache_manager.r.ttl(key))
        raise HTTPException(status_code=429, detail=f"Muitas requisições. Tente novamente em {ttl}s.")

    token = extract_sdwork_token(authorization)
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente ou inválido.")
    parsed = parse_token(token)
    if not parsed:
        raise HTTPException(status_code=400, detail="Token inválido.")
    email, document = parsed
    user = storage.find_user_by_email_and_document(email, document)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário não encontrado.")
    return user

@app.post(f"{API_PREFIX}/logout", response_model=schemas.MessageResponse, tags=["Autenticação"])
def logout():
    return {"message": "Logout efetuado com sucesso."}
