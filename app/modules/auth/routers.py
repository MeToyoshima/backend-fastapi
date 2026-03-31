# app/modules/auth/routers.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from core.database import SessionLocal
from modules.users.repositories import UserRepository
from core.security import verify_password, create_access_token
from modules.auth.schemas import Token

router = APIRouter(prefix="/auth", tags=["Autenticação"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    
    # 1. O OAuth2PasswordRequestForm guarda o email no campo 'username'
    user_repo = UserRepository(db)
    user = user_repo.get_by_email(email=form_data.username)
    
    # 2. Verificamos se o utilizador existe E se a palavra-passe bate com o hash
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou palavra-passe incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 3. Se passou na validação, criamos o Token (Crachá)
    # Colocamos o email e o perfil (role) dentro do token para uso futuro
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role}
    )
    
    # 4. Devolvemos o Token ao cliente
    return {"access_token": access_token, "token_type": "bearer"}