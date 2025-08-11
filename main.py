from fastapi import FastAPI, HTTPException, Body
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from datetime import datetime
import base64
import os

# Configuración de la BD (SQLite local)
DATABASE_URL = "sqlite:///./reports.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelo de BD
class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    photo_base64 = Column(String, nullable=False)  # Guardamos base64 directamente
    description = Column(String, nullable=True)  # Campo extra opcional

Base.metadata.create_all(bind=engine)

# Modelo Pydantic para validación
class ReportCreate(BaseModel):
    latitude: float
    longitude: float
    timestamp: datetime
    photo_base64: str
    description: str = None

class ReportResponse(ReportCreate):
    id: int

# Instancia de FastAPI
app = FastAPI(
    title="Reportes API",
    description="API para recibir y servir reportes con coordenadas GPS y fotos.",
    version="1.0.0"
)

# Endpoint POST para crear reporte
@app.post("/reports/", response_model=ReportResponse)
def create_report(report: ReportCreate = Body(...)):
    db = SessionLocal()
    try:
        db_report = Report(
            latitude=report.latitude,
            longitude=report.longitude,
            timestamp=report.timestamp,
            photo_base64=report.photo_base64,
            description=report.description
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        return db_report
    finally:
        db.close()

# Endpoint GET para obtener todos los reportes
@app.get("/reports/", response_model=list[ReportResponse])
def get_reports():
    db = SessionLocal()
    try:
        reports = db.query(Report).all()
        return reports
    finally:
        db.close()

# Endpoint GET para un reporte específico (opcional, pero útil)
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
        