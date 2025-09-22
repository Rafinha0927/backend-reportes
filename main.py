from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from datetime import datetime
import logging
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)

# Configuración de la base de datos PostgreSQL en AWS RDS
DATABASE_URL = "postgresql://postgres:Jd3201092@reports.c8f8a6g2c9he.us-east-1.rds.amazonaws.com:5432/reports"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Definición de la tabla de usuarios (solo definición, no creación)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# Dependencia para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Configuración de seguridad
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key"  # Cambia esto por una clave segura en producción
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Modelos Pydantic para validación
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

# Funciones de autenticación
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: int = 3600):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Crear la aplicación FastAPI
app = FastAPI(
    title="API de Reportes",
    description="API REST para recibir y servir reportes GPS con fotos y autenticación de usuarios.",
    version="1.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://18.233.249.90:5000"],  # Especifica el origen exacto
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Endpoints de autenticación
@app.post("/register/")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    db_user_email = db.query(User).filter(User.email == user.email).first()
    if db_user_email:
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Usuario registrado exitosamente", "username": user.username}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access_token = create_access_token(data={"sub": user.username})
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(key="session_token", value=access_token, httponly=True, max_age=3600, path="/", samesite="Lax")
    return response

@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    logging.debug(f"Verificando token en /: Cookie encontrada - {request.cookies.get('session_token')}")
    token = request.cookies.get("session_token")
    if not token:
        logging.debug("No se encontró token, redirigiendo a /login")
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    try:
        get_current_user(token, SessionLocal())
        logging.debug("Token válido, sirviendo index.html")
        with open("index.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except HTTPException as e:
        logging.debug(f"Token inválido: {str(e.detail)}, redirigiendo a /login")
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

@app.get("/login", response_class=HTMLResponse)
async def read_login():
    logging.debug("Sirviendo login.html")
    with open("login.html", "r", encoding="utf-8") as file:
        return HTMLResponse(content=file.read())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)