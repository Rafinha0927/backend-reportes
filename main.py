from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr, validator
from datetime import datetime
import json
import logging
from typing import List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)

# Configuración de la BD PostgreSQL en RDS
DATABASE_URL = "postgresql://postgres:Jd3201092@reports.c8f8a6g2c9he.us-east-1.rds.amazonaws.com:5432/reports"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Tabla de Usuarios
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

# Tabla de Reportes
class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    photo_base64 = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

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

# Modelos Pydantic
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    @validator('password')
    def password_length(cls, v):
        if len(v) < 6:
            raise ValueError('La contraseña debe tener al menos 6 caracteres')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class ReportCreate(BaseModel):
    latitude: float
    longitude: float
    timestamp: str
    photo_base64: str

    @validator('timestamp')
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError('El timestamp debe estar en formato ISO 8601 (ej. "2025-09-10T22:05:00-05:00")')

class ReportResponse(BaseModel):
    id: int
    latitude: float
    longitude: float
    timestamp: str
    photo_base64: str

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
        detail="No se pudo validar las credenciales",
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

# Crea la app FastAPI
app = FastAPI(
    title="API de Reportes",
    description="API REST para recibir y servir reportes GPS con fotos.",
    version="1.0.0"
)

# Configura CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origin_regex=r".*"  # Para WebSockets
)

# Lista de clientes conectados por WebSocket y contador de usuarios
connected_clients = []
connected_users = 0

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Depends(oauth2_scheme)):
    user = get_current_user(token, SessionLocal())
    await websocket.accept()
    connected_clients.append(websocket)
    global connected_users
    connected_users += 1
    await broadcast({"type": "user_count", "count": connected_users})

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        connected_users -= 1
        await broadcast({"type": "user_count", "count": connected_users})

async def broadcast(message: dict):
    message_json = json.dumps(message)
    for client in connected_clients[:]:
        try:
            await client.send_text(message_json)
        except:
            connected_clients.remove(client)

# Endpoints de autenticación
@app.post("/register/")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
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
    response.set_cookie(key="session_token", value=access_token, httponly=True, max_age=3600)
    return response

# Sirve index.html
@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        with open("login.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    try:
        get_current_user(token, SessionLocal())
        with open("index.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except HTTPException:
        with open("login.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())

@app.get("/reports/", response_model=List[ReportResponse], dependencies=[Depends(get_current_user)])
async def get_reports(db: Session = Depends(get_db)):
    logging.debug("Fetching all reports")
    try:
        reports = db.query(Report).all()
        return [
            {
                "id": r.id,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "timestamp": r.timestamp.isoformat(),
                "photo_base64": r.photo_base64
            } for r in reports
        ]
    except Exception as e:
        logging.error(f"Error fetching reports: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error")

@app.post("/reports/", response_model=ReportResponse, dependencies=[Depends(get_current_user)])
async def create_report(report: ReportCreate = Body(...), db: Session = Depends(get_db)):
    try:
        timestamp = datetime.fromisoformat(report.timestamp.replace('Z', '+00:00'))
        db_report = Report(
            latitude=report.latitude,
            longitude=report.longitude,
            timestamp=timestamp,
            photo_base64=report.photo_base64
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)

        response_data = {
            "id": db_report.id,
            "latitude": db_report.latitude,
            "longitude": db_report.longitude,
            "timestamp": db_report.timestamp.isoformat(),
            "photo_base64": db_report.photo_base64
        }

        new_report = {"type": "new_report", "data": response_data}
        await broadcast(new_report)

        return response_data
    finally:
        db.close()

@app.delete("/reports/{report_id}", dependencies=[Depends(get_current_user)])
async def delete_report(report_id: int, db: Session = Depends(get_db)):
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        if report is None:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")
        db.delete(report)
        db.commit()

        delete_message = {"type": "delete_report", "data": {"id": report_id}}
        await broadcast(delete_message)
        return {"message": "Reporte eliminado exitosamente"}
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)