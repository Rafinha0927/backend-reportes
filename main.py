from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, validator, EmailStr
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List, Optional
import json
import logging
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logging.basicConfig(level=logging.DEBUG)

# ==================== CONFIGURACIÓN ====================
# Configuración de seguridad JWT
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
PASSWORD_RESET_EXPIRE_MINUTES = 30

# Configuración de correo electrónico
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "tu_correo@gmail.com"  # CAMBIAR POR TU CORREO
SMTP_PASSWORD = "tu_app_password"  # CAMBIAR POR APP PASSWORD DE GMAIL
SMTP_FROM_EMAIL = "tu_correo@gmail.com"  # CAMBIAR POR TU CORREO
SMTP_FROM_NAME = "Reports Center"

# Configuración de la BD PostgreSQL en RDS
DATABASE_URL = "postgresql://postgres:Jd3201092@reports.c8f8a6g2c9he.us-east-1.rds.amazonaws.com:5432/reports"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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

Base.metadata.create_all(bind=engine)

# ==================== CONFIGURACIÓN DE SEGURIDAD ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==================== MODELOS PYDANTIC ====================
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

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

def create_password_reset_token(email: str):
    """Crea un token temporal para recuperación de contraseña"""
    expires = datetime.utcnow() + timedelta(minutes=PASSWORD_RESET_EXPIRE_MINUTES)
    to_encode = {
        "sub": email,
        "exp": expires,
        "type": "password_reset"
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password_reset_token(token: str) -> Optional[str]:
    """Verifica el token de recuperación y retorna el email"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if email is None or token_type != "password_reset":
            return None
        return email
    except JWTError:
        return None

def send_password_reset_email(email: str, token: str, base_url: str):
    """Envía el correo de recuperación de contraseña"""
    try:
        reset_link = f"{base_url}/reset-password?token={token}"
        
        message = MIMEMultipart("alternative")
        message["Subject"] = "Recuperación de Contraseña - Reports Center"
        message["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        message["To"] = email
        
        # Versión texto plano
        text = f"""
        Hola,
        
        Recibimos una solicitud para restablecer tu contraseña en Reports Center.
        
        Haz clic en el siguiente enlace para crear una nueva contraseña:
        {reset_link}
        
        Este enlace expirará en {PASSWORD_RESET_EXPIRE_MINUTES} minutos.
        
        Si no solicitaste este cambio, puedes ignorar este correo de forma segura.
        
        Saludos,
        El equipo de Reports Center
        """
        
        # Versión HTML
        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
              <div style="background-color: #ffffff; padding: 30px; border-radius: 10px;">
                <h2 style="color: #4A90E2; margin-bottom: 20px;">Recuperación de Contraseña</h2>
                <p>Hola,</p>
                <p>Recibimos una solicitud para restablecer tu contraseña en <strong>Reports Center</strong>.</p>
                <p>Haz clic en el siguiente botón para crear una nueva contraseña:</p>
                <div style="text-align: center; margin: 30px 0;">
                  <a href="{reset_link}" 
                     style="background-color: #4A90E2; 
                            color: white; 
                            padding: 12px 30px; 
                            text-decoration: none; 
                            border-radius: 5px; 
                            display: inline-block;">
                    Restablecer Contraseña
                  </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                  O copia y pega este enlace en tu navegador:<br>
                  <a href="{reset_link}" style="color: #4A90E2;">{reset_link}</a>
                </p>
                <p style="color: #999; font-size: 12px; margin-top: 20px;">
                  Este enlace expirará en {PASSWORD_RESET_EXPIRE_MINUTES} minutos por seguridad.
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="color: #999; font-size: 12px;">
                  Si no solicitaste este cambio, puedes ignorar este correo de forma segura.
                </p>
              </div>
            </div>
          </body>
        </html>
        """
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)
        
        # Enviar correo
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM_EMAIL, email, message.as_string())
        
        logging.info(f"Correo de recuperación enviado a {email}")
        return True
    except Exception as e:
        logging.error(f"Error enviando correo: {str(e)}")
        return False

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
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Solicita recuperación de contraseña - envía email con token"""
    user = db.query(User).filter(User.email == request.email).first()
    
    # Por seguridad, siempre respondemos lo mismo aunque el email no exista
    if not user:
        logging.warning(f"Intento de recuperación para email no registrado: {request.email}")
        return {
            "message": "Si el correo está registrado, recibirás un enlace de recuperación."
        }
    
    # Generar token de recuperación
    reset_token = create_password_reset_token(request.email)
    
    # Obtener la URL base de la solicitud
    base_url = "http://18.233.249.90:5000"  # Cambiar por tu dominio en producción
    
    # Enviar correo
    email_sent = send_password_reset_email(request.email, reset_token, base_url)
    
    if not email_sent:
        logging.error(f"Error enviando correo a {request.email}")
        # No revelamos el error real al usuario por seguridad
    
    return {
        "message": "Si el correo está registrado, recibirás un enlace de recuperación."
    }

@app.get("/reset-password", response_class=HTMLResponse)
async def show_reset_password_form(token: str):
    """Muestra el formulario de restablecimiento de contraseña"""
    # Verificar que el token sea válido
    email = verify_password_reset_token(token)
    if not email:
        return HTMLResponse(content="""
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Token Inválido</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        margin: 0;
                    }
                    .container {
                        background: white;
                        padding: 40px;
                        border-radius: 10px;
                        text-align: center;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    }
                    h1 { color: #e74c3c; }
                    a {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 10px 20px;
                        background: #3498db;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ Token Inválido o Expirado</h1>
                    <p>El enlace de recuperación no es válido o ha expirado.</p>
                    <a href="/">Volver al inicio</a>
                </div>
            </body>
            </html>
        """)
    
    # Si el token es válido, mostrar el formulario
    return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Restablecer Contraseña</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                body {{
                    font-family: 'Inter', sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }}
                .container {{
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    width: 100%;
                    max-width: 400px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    text-align: center;
                }}
                .subtitle {{
                    color: #666;
                    text-align: center;
                    margin-bottom: 30px;
                    font-size: 14px;
                }}
                .form-group {{
                    margin-bottom: 20px;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #333;
                    font-weight: 500;
                }}
                input {{
                    width: 100%;
                    padding: 12px;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    font-size: 14px;
                }}
                input:focus {{
                    outline: none;
                    border-color: #667eea;
                }}
                button {{
                    width: 100%;
                    padding: 14px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s;
                }}
                button:hover {{
                    transform: translateY(-2px);
                }}
                .message {{
                    padding: 12px;
                    border-radius: 8px;
                    margin-top: 15px;
                    display: none;
                }}
                .error {{
                    background: #fee;
                    color: #c33;
                    border: 1px solid #fcc;
                }}
                .success {{
                    background: #efe;
                    color: #3c3;
                    border: 1px solid #cfc;
                }}
                .requirements {{
                    font-size: 12px;
                    color: #666;
                    margin-top: 8px;
                    padding: 10px;
                    background: #f9f9f9;
                    border-radius: 5px;
                }}
                .requirement {{
                    margin: 4px 0;
                }}
                .requirement.met {{
                    color: #3c3;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Restablecer Contraseña</h1>
                <p class="subtitle">Ingresa tu nueva contraseña</p>
                
                <form id="resetForm">
                    <div class="form-group">
                        <label for="password">Nueva Contraseña</label>
                        <input type="password" id="password" name="password" required minlength="8">
                        <div class="requirements">
                            <div class="requirement" id="req-length">○ Mínimo 8 caracteres</div>
                            <div class="requirement" id="req-uppercase">○ Una letra mayúscula</div>
                            <div class="requirement" id="req-lowercase">○ Una letra minúscula</div>
                            <div class="requirement" id="req-number">○ Un número</div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="confirmPassword">Confirmar Contraseña</label>
                        <input type="password" id="confirmPassword" name="confirmPassword" required>
                    </div>
                    <button type="submit">Restablecer Contraseña</button>
                    <div class="message error" id="errorMessage"></div>
                    <div class="message success" id="successMessage"></div>
                </form>
            </div>

            <script>
                const token = '{token}';
                const password = document.getElementById('password');
                const confirmPassword = document.getElementById('confirmPassword');
                
                // Validación en tiempo real
                password.addEventListener('input', () => {{
                    const value = password.value;
                    
                    document.getElementById('req-length').classList.toggle('met', value.length >= 8);
                    document.getElementById('req-uppercase').classList.toggle('met', /[A-Z]/.test(value));
                    document.getElementById('req-lowercase').classList.toggle('met', /[a-z]/.test(value));
                    document.getElementById('req-number').classList.toggle('met', /\\d/.test(value));
                }});
                
                document.getElementById('resetForm').addEventListener('submit', async (e) => {{
                    e.preventDefault();
                    
                    const pwd = password.value;
                    const confirm = confirmPassword.value;
                    
                    // Validaciones
                    if (pwd !== confirm) {{
                        showError('Las contraseñas no coinciden');
                        return;
                    }}
                    
                    if (pwd.length < 8 || !/[A-Z]/.test(pwd) || !/[a-z]/.test(pwd) || !/\\d/.test(pwd)) {{
                        showError('La contraseña no cumple los requisitos mínimos');
                        return;
                    }}
                    
                    try {{
                        const response = await fetch('/reset-password/', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }},
                            body: JSON.stringify({{
                                token: token,
                                new_password: pwd
                            }})
                        }});
                        
                        const data = await response.json();
                        
                        if (response.ok) {{
                            showSuccess(data.message);
                            setTimeout(() => {{
                                window.location.href = '/';
                            }}, 2000);
                        }} else {{
                            showError(data.detail || 'Error al restablecer contraseña');
                        }}
                    }} catch (error) {{
                        showError('Error de conexión. Intenta nuevamente.');
                    }}
                }});
                
                function showError(message) {{
                    const errorDiv = document.getElementById('errorMessage');
                    errorDiv.textContent = message;
                    errorDiv.style.display = 'block';
                    document.getElementById('successMessage').style.display = 'none';
                }}
                
                function showSuccess(message) {{
                    const successDiv = document.getElementById('successMessage');
                    successDiv.textContent = message;
                    successDiv.style.display = 'block';
                    document.getElementById('errorMessage').style.display = 'none';
                }}
            </script>
        </body>
        </html>
    """)

@app.post("/reset-password/")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Restablece la contraseña del usuario"""
    # Verificar token
    email = verify_password_reset_token(request.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token inválido o expirado"
        )
    
    # Buscar usuario
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )
    
    # Actualizar contraseña
    user.hashed_password = get_password_hash(request.new_password)
    db.commit()
    
    logging.info(f"Contraseña actualizada para usuario: {user.username}")
    
    return {"message": "Contraseña actualizada exitosamente. Ya puedes iniciar sesión."}

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
    message_json = json.dumps(message)
    for client in connected_clients[:]:
        try:
            await client.send_text(message_json)
        except:
            connected_clients.remove(client)

# ==================== ENDPOINTS DE PÁGINAS HTML ====================
@app.get("/", response_class=HTMLResponse)
async def serve_login():
    try:
        with open("login.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: login.html no encontrado</h1>", status_code=404)

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    try:
        import os
        file_path = os.path.join(os.path.dirname(__file__), "index.html")
        with open(file_path, "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: index.html no encontrado</h1>", status_code=404)

@app.get("/login", response_class=HTMLResponse)
async def serve_login_explicit():
    try:
        with open("login.html", "r", encoding="utf-8") as file:
            return HTMLResponse(content=file.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Error: login.html no encontrado</h1>", status_code=404)

# ==================== ENDPOINTS DE REPORTES ====================
@app.get("/reports/", response_model=List[ReportResponse])
async def get_reports(db: Session = Depends(get_db)):
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
    current_user: User = Depends(get_current_user)
):
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