from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, validator, Field
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List, Optional, Dict
import json
import logging
import secrets
import smtplib
import uuid
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

# ==================== CONFIGURACIÓN DE EMAIL ====================
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_HOST_USER = "tu_email@gmail.com"  # CAMBIAR POR TU EMAIL
EMAIL_HOST_PASSWORD = "tu_app_password"  # CAMBIAR POR TU APP PASSWORD DE GMAIL
EMAIL_USE_TLS = True

# Almacén temporal para tokens de recuperación (en producción usar Redis)
password_reset_tokens: Dict[str, dict] = {}

# ==================== MODELOS DE BASE DE DATOS ====================
class User(Base):
    __tablename__ = "public.users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = "public.reports"
    id = Column(Integer, primary_key=True, index=True)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    photo_base64 = Column(Text, nullable=False)
    city = Column(String, nullable=True)
    incident_type = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    status = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    user_id = Column(Integer, nullable=True)

# Crear todas las tablas
Base.metadata.create_all(bind=engine)

# ==================== CONFIGURACIÓN DE SEGURIDAD ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==================== FUNCIONES DE VALIDACIÓN ====================
def validate_password_strength(password: str) -> tuple[bool, str]:
    """Valida que la contraseña cumpla con los requisitos de seguridad"""
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if len(password) > 128:
        return False, "La contraseña no puede exceder 128 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una letra mayúscula"
    
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una letra minúscula"
    
    if not re.search(r'\d', password):
        return False, "La contraseña debe contener al menos un número"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;`~]', password):
        return False, "La contraseña debe contener al menos un carácter especial (!@#$%^&*...)"
    
    # Verificar contraseñas comunes
    common_passwords = [
        "Password1!", "Password123!", "Admin123!", "Welcome1!", 
        "Qwerty123!", "Abc123456!", "Password1234!"
    ]
    if password in common_passwords:
        return False, "Esta contraseña es demasiado común, elige una diferente"
    
    return True, "Contraseña válida"

# ==================== MODELOS PYDANTIC ====================
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., regex=r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    password: str = Field(..., min_length=8, max_length=128)
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('El nombre de usuario solo puede contener letras, números y guiones bajos')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        is_valid, message = validate_password_strength(v)
        if not is_valid:
            raise ValueError(message)
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class PasswordResetRequest(BaseModel):
    email: str = Field(..., regex=r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)
    
    @validator('new_password')
    def validate_new_password(cls, v):
        is_valid, message = validate_password_strength(v)
        if not is_valid:
            raise ValueError(message)
        return v

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

# ==================== FUNCIONES DE EMAIL ====================
def send_password_reset_email(email: str, token: str, base_url: str) -> bool:
    """Envía email de recuperación de contraseña"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Reports Center - Recuperación de Contraseña"
        msg['From'] = EMAIL_HOST_USER
        msg['To'] = email
        
        reset_link = f"{base_url}reset-password?token={token}"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #3b82f6, #8b5cf6); padding: 30px; text-align: center; }}
                .header h1 {{ color: white; margin: 0; font-size: 24px; }}
                .content {{ padding: 30px; }}
                .button {{ display: inline-block; padding: 15px 30px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 14px; }}
                .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; color: #856404; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📍 Reports Center</h1>
                </div>
                <div class="content">
                    <h2>Recuperación de Contraseña</h2>
                    <p>Hola,</p>
                    <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta en Reports Center.</p>
                    <p>Si solicitaste este cambio, haz clic en el siguiente botón:</p>
                    <div style="text-align: center;">
                        <a href="{reset_link}" class="button">Restablecer Contraseña</a>
                    </div>
                    <p>O copia y pega este enlace en tu navegador:</p>
                    <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace;">
                        {reset_link}
                    </p>
                    <div class="warning">
                        <strong>⚠️ Importante:</strong>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li>Este enlace expira en 1 hora por seguridad</li>
                            <li>Si no solicitaste este cambio, ignora este email</li>
                            <li>Tu contraseña actual sigue siendo válida hasta que la cambies</li>
                        </ul>
                    </div>
                </div>
                <div class="footer">
                    <p>Este mensaje fue enviado automáticamente desde Reports Center</p>
                    <p>Si tienes problemas, contacta al administrador del sistema</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        html_part = MIMEText(html, 'html')
        msg.attach(html_part)
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_HOST_USER, email, text)
        server.quit()
        
        logging.info(f"Email de recuperación enviado a {email}")
        return True
        
    except Exception as e:
        logging.error(f"Error enviando email: {e}")
        return False

def generate_reset_token(email: str) -> str:
    """Genera token único para recuperación"""
    token = str(uuid.uuid4())
    
    password_reset_tokens[token] = {
        'email': email,
        'created_at': datetime.utcnow(),
        'used': False
    }
    
    return token

def validate_reset_token(token: str) -> Optional[str]:
    """Valida token de recuperación y retorna email si es válido"""
    if token not in password_reset_tokens:
        return None
        
    token_data = password_reset_tokens[token]
    
    if token_data['used']:
        return None
    
    if datetime.utcnow() - token_data['created_at'] > timedelta(hours=1):
        del password_reset_tokens[token]
        return None
    
    return token_data['email']

def cleanup_expired_tokens():
    """Limpia tokens expirados"""
    current_time = datetime.utcnow()
    expired_tokens = [
        token for token, data in password_reset_tokens.items()
        if current_time - data['created_at'] > timedelta(hours=1)
    ]
    
    for token in expired_tokens:
        del password_reset_tokens[token]
    
    logging.info(f"Limpiados {len(expired_tokens)} tokens expirados")

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
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# ==================== VARIABLES GLOBALES ====================
connected_clients = []
connected_users = 0

# ==================== ENDPOINTS DE AUTENTICACIÓN ====================
@app.post("/register/", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    """Registra un nuevo usuario"""
    db_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if db_user:
        if db_user.username == user.username:
            raise HTTPException(status_code=400, detail="El nombre de usuario ya está registrado")
        else:
            raise HTTPException(status_code=400, detail="El email ya está registrado")
    
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

# ==================== ENDPOINTS DE RECUPERACIÓN DE CONTRASEÑA ====================
@app.post("/forgot-password/")
async def forgot_password(request_data: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    """Solicita recuperación de contraseña por email"""
    try:
        # Obtener base URL del request
        base_url = str(request.base_url)
        
        user = db.query(User).filter(User.email == request_data.email).first()
        
        response_message = "Si el email está registrado, recibirás instrucciones para recuperar tu contraseña."
        
        if user:
            token = generate_reset_token(request_data.email)
            email_sent = send_password_reset_email(request_data.email, token, base_url)
            
            if email_sent:
                logging.info(f"Token de recuperación generado para {request_data.email}")
            else:
                logging.error(f"Error enviando email a {request_data.email}")
        
        return {"message": response_message}
        
    except Exception as e:
        logging.error(f"Error en forgot_password: {e}")
        raise HTTPException(status_code=500, detail="Error procesando solicitud")

@app.post("/reset-password/")
async def reset_password(reset_data: PasswordResetConfirm, db: Session = Depends(get_db)):
    """Confirma el cambio de contraseña con token"""
    try:
        email = validate_reset_token(reset_data.token)
        if not email:
            raise HTTPException(
                status_code=400, 
                detail="Token inválido o expirado. Solicita una nueva recuperación."
            )
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        new_hashed_password = get_password_hash(reset_data.new_password)
        user.hashed_password = new_hashed_password
        
        password_reset_tokens[reset_data.token]['used'] = True
        
        db.commit()
        
        logging.info(f"Contraseña actualizada para usuario {user.username}")
        
        return {"message": "Contraseña actualizada exitosamente. Ya puedes iniciar sesión."}
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error en reset_password: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Error actualizando contraseña")

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(token: str):
    """Página para restablecer contraseña"""
    email = validate_reset_token(token)
    if not email:
        return HTMLResponse(content="""
        <html>
            <head>
                <title>Token Inválido</title>
                <style>
                    body { font-family: Arial; text-align: center; padding: 50px; background: #f4f4f4; }
                    .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .button { display: inline-block; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>⚠️ Token Inválido</h1>
                    <p>El enlace ha expirado o ya fue utilizado.</p>
                    <a href="/" class="button">Solicitar nueva recuperación</a>
                </div>
            </body>
        </html>
        """)
    
    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Restablecer Contraseña - Reports Center</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; padding: 20px; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
            .container {{ max-width: 400px; background: rgba(255, 255, 255, 0.95); padding: 40px; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); backdrop-filter: blur(10px); }}
            h2 {{ text-align: center; color: #333; margin-bottom: 10px; }}
            .subtitle {{ text-align: center; color: #666; margin-bottom: 30px; font-size: 14px; }}
            input {{ width: 100%; padding: 15px; margin: 10px 0; border: 2px solid #ddd; border-radius: 10px; font-size: 16px; transition: all 0.3s ease; }}
            input:focus {{ outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }}
            button {{ width: 100%; padding: 15px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; }}
            button:hover {{ transform: translateY(-2px); box-shadow: 0 10px 20px rgba(59, 130, 246, 0.3); }}
            button:disabled {{ opacity: 0.6; cursor: not-allowed; }}
            .message {{ padding: 15px; margin: 15px 0; border-radius: 8px; text-align: center; }}
            .error {{ background: #fee; border: 1px solid #fcc; color: #c33; }}
            .success {{ background: #efe; border: 1px solid #cfc; color: #3c3; }}
            .requirements {{ font-size: 12px; color: #666; margin: 15px 0; background: #f8f9fa; padding: 15px; border-radius: 8px; }}
            .requirements ul {{ margin: 5px 0; padding-left: 20px; }}
            .requirements li {{ margin: 5px 0; }}
            .loading {{ opacity: 0.7; pointer-events: none; }}
            .spinner {{ display: none; width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.3); border-top: 2px solid white; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto; }}
            @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
            .loading .spinner {{ display: block; }}
            .loading .button-text {{ display: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔒 Restablecer Contraseña</h2>
            <p class="subtitle">Cuenta: <strong>{email}</strong></p>
            
            <form id="resetForm">
                <input type="password" id="newPassword" placeholder="Nueva contraseña" required>
                <input type="password" id="confirmPassword" placeholder="Confirmar contraseña" required>
                
                <div class="requirements">
                    <strong>Requisitos de la contraseña:</strong>
                    <ul>
                        <li>Mínimo 8 caracteres</li>
                        <li>Una letra mayúscula</li>
                        <li>Una letra minúscula</li>
                        <li>Un número</li>
                        <li>Un carácter especial (!@#$%...)</li>
                    </ul>
                </div>
                
                <button type="submit" id="submitBtn">
                    <span class="button-text">Cambiar Contraseña</span>
                    <div class="spinner"></div>
                </button>
            </form>
            
            <div id="message" class="message" style="display: none;"></div>
        </div>

        <script>
            document.getElementById('resetForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                
                const newPassword = document.getElementById('newPassword').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                const messageDiv = document.getElementById('message');
                const submitBtn = document.getElementById('submitBtn');
                
                if (newPassword !== confirmPassword) {{
                    messageDiv.textContent = 'Las contraseñas no coinciden';
                    messageDiv.className = 'message error';
                    messageDiv.style.display = 'block';
                    return;
                }}
                
                submitBtn.classList.add('loading');
                submitBtn.disabled = true;
                
                try {{
                    const response = await fetch('/reset-password/', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            token: '{token}',
                            new_password: newPassword
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    if (response.ok) {{
                        messageDiv.textContent = data.message;
                        messageDiv.className = 'message success';
                        messageDiv.style.display = 'block';
                        
                        setTimeout(() => {{
                            window.location.href = '/';
                        }}, 2000);
                    }} else {{
                        messageDiv.textContent = data.detail;
                        messageDiv.className = 'message error';
                        messageDiv.style.display = 'block';
                    }}
                }} catch (error) {{
                    messageDiv.textContent = 'Error de conexión';
                    messageDiv.className = 'message error';
                    messageDiv.style.display = 'block';
                }} finally {{
                    submitBtn.classList.remove('loading');
                    submitBtn.disabled = false;
                }}
            }});
        </script>
    </body>
    </html>
    """)

# ==================== WEBSOCKET ====================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
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
    """Envía mensaje a todos los clientes WebSocket conectados"""
    message_json = json.dumps(message)
    for client in connected_clients[:]:
        try:
            await client.send_text(message_json)
        except:
            connected_clients.remove(client)

# ==================== ENDPOINTS DE PÁGINAS HTML ====================
@app.get("/", response_class=HTMLResponse)
async def serve_login():
    """Sirve la página de login como raíz"""
    try:
        with open("login.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: index.html no encontrado</h1>", status_code=404)

@app.get("/login", response_class=HTMLResponse)
async def serve_login_explicit():
    """Sirve la página de login explícitamente (opcional)"""
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

# ==================== EVENTO DE INICIO ====================
@app.on_event("startup")
async def startup_event():
    """Ejecuta tareas de inicio"""
    cleanup_expired_tokens()
    logging.info("Aplicación iniciada - Sistema de recuperación de contraseñas activado")

# ==================== TAREA PROGRAMADA PARA LIMPIEZA ====================
# En producción, usar APScheduler o Celery para tareas programadas
import asyncio

async def periodic_cleanup():
    """Limpieza periódica de tokens expirados cada 30 minutos"""
    while True:
        await asyncio.sleep(1800)  # 30 minutos
        cleanup_expired_tokens()

@app.on_event("startup")
async def start_background_tasks():
    """Inicia tareas en segundo plano"""
    asyncio.create_task(periodic_cleanup())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)<h1>Error: login.html no encontrado</h1>", status_code=404)


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """
    Sirve el dashboard principal (index.html).
    El frontend verifica el token y redirige a / si no está autenticado.
    """
    try:
        import os
        file_path = os.path.join(os.path.dirname(__file__), "index.html")
        with open(file_path, "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: index.html no encontrado</h1>", status_code=404)

@app.get("/login", response_class=HTMLResponse)
async def serve_login_explicit():
    """
    Sirve la página de login explícitamente (opcional).
    """
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
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)