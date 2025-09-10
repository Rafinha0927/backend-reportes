from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from datetime import datetime
import json

# Configuración de la BD PostgreSQL en RDS
DATABASE_URL = "postgresql://postgres:Jd3201092@reports.c8f8a6g2c9he.us-east-1.rds.amazonaws.com:5432/reports"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    photo_base64 = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

class ReportCreate(BaseModel):
    latitude: float
    longitude: float
    timestamp: str  # Recibe como cadena ISO
    photo_base64: str

class ReportResponse(ReportCreate):
    id: int

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

# Lista de clientes conectados por WebSocket
connected_clients = []

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

# Sirve index.html
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r", encoding="utf-8") as file:
        return HTMLResponse(content=file.read())

@app.post("/reports/", response_model=ReportResponse)
async def create_report(report: ReportCreate = Body(...)):
    db = SessionLocal()
    try:
        # Depuración
        print(f"Received timestamp: {report.timestamp}")
        # Validar y convertir el timestamp
        if not report.timestamp or not isinstance(report.timestamp, str):
            raise HTTPException(status_code=400, detail="Timestamp inválido o ausente")
        try:
            report_timestamp = datetime.fromisoformat(report.timestamp.replace('Z', '+00:00'))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Formato de timestamp inválido: {e}")
        
        db_report = Report(
            latitude=report.latitude,
            longitude=report.longitude,
            timestamp=report_timestamp,
            photo_base64=report.photo_base64
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        # Convierte timestamp a cadena ISO explícitamente
        timestamp_str = db_report.timestamp.isoformat() + 'Z' if isinstance(db_report.timestamp, datetime) else db_report.timestamp
        
        # Broadcast del nuevo reporte
        new_report_json = json.dumps({
            "id": db_report.id,
            "latitude": db_report.latitude,
            "longitude": db_report.longitude,
            "timestamp": timestamp_str,
            "photo_base64": db_report.photo_base64
        })
        print(f"Broadcasting: {new_report_json}")
        for client in connected_clients[:]:
            try:
                await client.send_text(new_report_json)
                print(f"Mensaje enviado a cliente: {client.client}")
            except Exception as e:
                print(f"Error enviando a cliente: {e}")
                connected_clients.remove(client)
        # Devuelve un diccionario con timestamp como cadena
        return {
            "id": db_report.id,
            "latitude": db_report.latitude,
            "longitude": db_report.longitude,
            "timestamp": timestamp_str,
            "photo_base64": db_report.photo_base64
        }
    finally:
        db.close()

@app.delete("/reports/{report_id}")
async def delete_report(report_id: int):
    db = SessionLocal()
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        if report is None:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")
        db.delete(report)
        db.commit()
        
        # Broadcast de eliminación
        delete_message = json.dumps({"action": "delete", "id": report_id})
        for client in connected_clients[:]:
            try:
                await client.send_text(delete_message)
            except:
                connected_clients.remove(client)
        return {"message": "Reporte eliminado exitosamente"}
    finally:
        db.close()