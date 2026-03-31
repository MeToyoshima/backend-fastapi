from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import jwt
from core.config import settings

# 1. Configuração do "Triturador" de Senhas (Bcrypt)
# Dizemos ao passlib que queremos usar o algoritmo bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """Recebe a senha em texto limpo e devolve o hash embaralhado."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha digitada no login bate com o hash salvo no banco."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    """Gera o token JWT contendo os dados do usuário e a validade."""
    
    # Fazemos uma cópia dos dados (payload) para não alterar o dicionário original
    to_encode = data.copy()
    
    # Definimos quando o token vai expirar (ex: agora + 30 minutos)
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Adicionamos a data de expiração ('exp' é um padrão do JWT) ao payload
    to_encode.update({"exp": expire})
    
    # Assinamos o token usando a nossa chave secreta e o algoritmo escolhido
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    return encoded_jwt