from pydantic import BaseModel

# Este é o formato padrão que o FastAPI espera para devolver o Token
class Token(BaseModel):
    access_token: str
    token_type: str