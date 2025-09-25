from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, validator
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List, Optional
import json
import logging
import secrets

logging.basicConfig(level=logging.DEBUG)

# ==================== CONFIGURACIÓN ====================
# Configuración de seguridad JWT
SECRET_KEY = secrets.token_urlsafe(32)  # Genera una clave segura automáticamente
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configuración de la BD PostgreSQL en RDS (tu configuración actual)
DATABASE_URL = "postgresql://postgres:Jd3201092@reports.c8f8a6g2c9he.us-east-1.rds.amazonaws.com:5432/reports"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==================== MODELOS DE BASE DE DATOS ====================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    photo_base64 = Column(Text, nullable=False)  # Cambiado a Text para soportar imágenes grandes
    city = Column(String, nullable=True)
    incident_type = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    status = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    user_id = Column(Integer, nullable=True)  # Para asociar reportes con usuarios

# Crear todas las tablas
Base.metadata.create_all(bind=engine)

# ==================== CONFIGURACIÓN DE SEGURIDAD ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==================== MODELOS PYDANTIC ====================
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ReportCreate(BaseModel):
    latitude: float
    longitude: float
    timestamp: str
    photo_base64: str
    city: Optional[str] = None
    incident_type: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = "Pendiente"
    description: Optional[str] = None

    @validator('timestamp')
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError('El timestamp debe estar en formato ISO 8601')

class ReportResponse(BaseModel):
    id: int
    latitude: float
    longitude: float
    timestamp: str
    photo_base64: str
    city: Optional[str] = None
    incident_type: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None

# ==================== FUNCIONES DE UTILIDAD ====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

# ==================== CREAR APP FASTAPI ====================
app = FastAPI(
    title="API de Reportes - Reports Center",
    description="API REST con autenticación para gestión de reportes GPS con fotos.",
    version="2.0.0"
)

# Configura CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_origin_regex=r".*"
)

# ==================== VARIABLES GLOBALES ====================
connected_clients = []
connected_users = 0

# ==================== ENDPOINTS DE AUTENTICACIÓN ====================
@app.post("/register/", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    """Registra un nuevo usuario"""
    # Verificar si el usuario ya existe
    db_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if db_user:
        if db_user.username == user.username:
            raise HTTPException(status_code=400, detail="El nombre de usuario ya está registrado")
        else:
            raise HTTPException(status_code=400, detail="El email ya está registrado")
    
    # Crear nuevo usuario
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return {"message": "Usuario registrado exitosamente", "username": db_user.username}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login de usuario - devuelve JWT token"""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Obtiene información del usuario actual"""
    return {
        "username": current_user.username,
        "email": current_user.email,
        "is_active": current_user.is_active
    }

# ==================== WEBSOCKET ====================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    global connected_users
    connected_users += 1
    
    # Broadcast del contador de usuarios
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
    """Envía mensaje a todos los clientes WebSocket conectados"""
    message_json = json.dumps(message)
    for client in connected_clients[:]:
        try:
            await client.send_text(message_json)
        except:
            connected_clients.remove(client)

# ==================== ENDPOINTS DE PÁGINAS HTML ====================
@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Redirige a login si no hay autenticación, o sirve index.html si la hay"""
    # Primero intentamos servir la página de login
    # El JavaScript en el frontend manejará la verificación del token
    try:
        # Verificar si existe un token en las cookies o localStorage (esto se hace en el frontend)
        # Por ahora, servimos login.html como página principal
        with open("login.html", "r", encoding="utf-8") as file:
            login_content = file.read()
            # Modificamos el script para que verifique si hay token y redirija automáticamente
            login_with_redirect = login_content.replace(
                "window.addEventListener('DOMContentLoaded', () => {",
                """window.addEventListener('DOMContentLoaded', () => {
                    // Verificar si ya hay un token válido
                    const token = localStorage.getItem('access_token');
                    if (token) {
                        // Verificar que el token sea válido antes de redirigir
                        fetch('/users/me', {
                            headers: { 'Authorization': `Bearer ${token}` }
                        })
                        .then(response => {
                            if (response.ok) {
                                // Token válido, redirigir al dashboard
                                window.location.href = '/dashboard';
                            }
                        })
                        .catch(() => {
                            // Error de red, mantener en login
                        });
                    }
                """
            )
            return HTMLResponse(content=login_with_redirect)
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: login.html no encontrado</h1>", status_code=404)

@app.get("/dashboard", response_class=HTMLResponse)
async def read_dashboard():
    """Sirve el dashboard principal (index.html)"""
    try:
        with open("index.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: index.html no encontrado</h1>", status_code=404)

@app.get("/login", response_class=HTMLResponse)
async def read_login():
    """Sirve la página de login explícitamente"""
    try:
        with open("login.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: login.html no encontrado</h1>", status_code=404)

# ==================== ENDPOINTS DE REPORTES ====================
@app.get("/reports/", response_model=List[ReportResponse])
async def get_reports(db: Session = Depends(get_db)):
    """Obtiene todos los reportes (público por ahora, puede requerir auth)"""
    logging.debug("Fetching all reports")
    try:
        reports = db.query(Report).order_by(Report.timestamp.desc()).all()
        return [
            {
                "id": r.id,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "timestamp": r.timestamp.isoformat(),
                "photo_base64": r.photo_base64,
                "city": r.city,
                "incident_type": r.incident_type,
                "severity": r.severity,
                "status": r.status,
                "description": r.description
            } for r in reports
        ]
    except Exception as e:
        logging.error(f"Error fetching reports: {str(e)}")
        raise HTTPException(status_code=500, detail="Error en la base de datos")

@app.post("/reports/", response_model=ReportResponse)
async def create_report(
    report: ReportCreate = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)  # Requiere autenticación
):
    """Crea un nuevo reporte (requiere autenticación)"""
    try:
        timestamp = datetime.fromisoformat(report.timestamp.replace('Z', '+00:00'))
        db_report = Report(
            latitude=report.latitude,
            longitude=report.longitude,
            timestamp=timestamp,
            photo_base64=report.photo_base64,
            city=report.city,
            incident_type=report.incident_type,
            severity=report.severity,
            status=report.status or "Pendiente",
            description=report.description,
            user_id=current_user.id  # Asociar con el usuario
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        response_data = {
            "id": db_report.id,
            "latitude": db_report.latitude,
            "longitude": db_report.longitude,
            "timestamp": db_report.timestamp.isoformat(),
            "photo_base64": db_report.photo_base64,
            "city": db_report.city,
            "incident_type": db_report.incident_type,
            "severity": db_report.severity,
            "status": db_report.status,
            "description": db_report.description
        }
        
        # Broadcast del nuevo reporte
        await broadcast({
            "type": "new_report",
            "data": response_data
        })
        
        return response_data
    except Exception as e:
        logging.error(f"Error creating report: {str(e)}")
        raise HTTPException(status_code=500, detail="Error creando el reporte")

@app.delete("/reports/{report_id}")
async def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)  # Requiere autenticación
):
    """Elimina un reporte (requiere autenticación)"""
    report = db.query(Report).filter(Report.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    
    db.delete(report)
    db.commit()
    
    # Broadcast de eliminación
    await broadcast({"type": "delete_report", "data": {"id": report_id}})
    
    return {"message": "Reporte eliminado exitosamente", "id": report_id}

@app.get("/stats/")
async def get_stats(db: Session = Depends(get_db)):
    """Obtiene estadísticas del sistema"""
    total_reports = db.query(Report).count()
    active_reports = db.query(Report).filter(Report.status != "Resuelto").count()
    total_users = db.query(User).count()
    
    return {
        "connected_users": connected_users,
        "total_reports": total_reports,
        "active_reports": active_reports,
        "resolved_reports": total_reports - active_reports,
        "total_users": total_users,
        "response_time": "2.3s",
        "uptime": "99.9%"
    }

@app.get("/health")
async def health_check():
    """Endpoint de verificación de salud del sistema"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "connected_websockets": len(connected_clients),
        "version": "2.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Iniciando Reports Center con Sistema de Autenticación")
    print("📊 Aplicación web: http://localhost:8000")
    print("🔐 Login: http://localhost:8000/login")
    print("📋 API Docs: http://localhost:8000/docs")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)