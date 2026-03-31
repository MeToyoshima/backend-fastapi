from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import jwt

from core.config import settings
from core.database import SessionLocal
from modules.users.repositories import UserRepository

# 1. Este é o "detetor de crachás". 
# Ele vai procurar o Token no cabeçalho (Header) da requisição.
# O 'tokenUrl' diz ao Swagger onde é que o utilizador deve ir para obter o Token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Função que já tínhamos para abrir a base de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Preparamos a mensagem de erro padrão caso ele seja barrado
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais (Token inválido ou expirado)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Tentamos ler decodificar o JWT com a nossa chave secreta
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        # Lembre-se que, no login, guardámos o email na variável "sub" (subject)
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
            
    except jwt.InvalidTokenError:
        raise credentials_exception

    user_repo = UserRepository(db)
    user = user_repo.get_by_email(email=email)
    
    if user is None:
        raise credentials_exception
        
    # Tudo certo!
    return user