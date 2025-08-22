from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from datetime import datetime
import json

# Configuración de la BD
DATABASE_URL = "sqlite:///./reports.db"
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
    timestamp: datetime
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
            data = await websocket.receive_text()  # Mantiene la conexión abierta
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

# Sirve index.html en la raíz
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r", encoding="utf-8") as file:
        return HTMLResponse(content=file.read())

@app.post("/reports/", response_model=ReportResponse)
def create_report(report: ReportCreate = Body(...)):
    db = SessionLocal()
    try:
        db_report = Report(
            latitude=report.latitude,
            longitude=report.longitude,
            timestamp=report.timestamp,
            photo_base64=report.photo_base64
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        # Broadcast del nuevo reporte a todos los clientes WebSocket
        new_report_json = json.dumps({
            "id": db_report.id,
            "latitude": db_report.latitude,
            "longitude": db_report.longitude,
            "timestamp": db_report.timestamp.isoformat(),
            "photo_base64": db_report.photo_base64
        })
        for client in connected_clients[:]:  # Copia para evitar errores durante iteración
            try:
                client.send_text(new_report_json)
            except:
                connected_clients.remove(client)
        
        return db_report
    finally:
        db.close()

@app.get("/reports/", response_model=list[ReportResponse])
def get_reports():
    db = SessionLocal()
    try:
        reports = db.query(Report).all()
        return reports
    finally:
        db.close()

@app.get("/reports/{report_id}", response_model=ReportResponse)
def get_report(report_id: int):
    db = SessionLocal()
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        if report is None:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")
        return report
    finally:
        db.close()

@app.delete("/reports/{report_id}")
def delete_report(report_id: int):
    db = SessionLocal()
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        if report is None:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")
        db.delete(report)
        db.commit()
        
        # Opcional: Broadcast de eliminación para actualizar clientes en tiempo real
        delete_message = json.dumps({"action": "delete", "id": report_id})
        for client in connected_clients[:]:
            try:
                client.send_text(delete_message)
            except:
                connected_clients.remove(client)
        
        return {"message": "Reporte eliminado exitosamente"}
    finally:
        db.close()