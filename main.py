from fastapi import FastAPI, HTTPException, Body, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel, validator
from datetime import datetime
import json
import logging
from typing import List

logging.basicConfig(level=logging.DEBUG)

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
    timestamp: str  # Explícitamente str para validación
    photo_base64: str

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

# Sirve index.html
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r", encoding="utf-8") as file:
        return HTMLResponse(content=file.read())

@app.get("/reports/", response_model=List[ReportResponse])
async def get_reports():
    logging.debug("Fetching all reports")
    db = SessionLocal()
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
    finally:
        db.close()

@app.post("/reports/", response_model=ReportResponse)
async def create_report(report: ReportCreate = Body(...)):
    db = SessionLocal()
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

        # Broadcast del nuevo reporte
        new_report = {
            "type": "new_report",
            "data": response_data
        }
        await broadcast(new_report)

        return response_data
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
        delete_message = {"type": "delete_report", "data": {"id": report_id}}
        await broadcast(delete_message)
        return {"message": "Reporte eliminado exitosamente"}
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)