"""
Quantum-Ready Cybersecurity Scanner — Main FastAPI Application
Modified for flat project structure.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import local files directly (no folders)
from db import init_db
import scan
import dashboard

app = FastAPI(
    title="Quantum-Ready Cybersecurity Scanner",
    description="CBOM Generator & PQC Validator for Banking-Grade TLS Endpoints",
    version="1.0.0",
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers directly
app.include_router(scan.router, prefix="/api/scan", tags=["Scanner"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])


@app.on_event("startup")
async def startup():
    init_db()


@app.get("/")
async def root():
    return {
        "service": "Quantum-Ready Cybersecurity Scanner",
        "status": "operational",
        "version": "1.0.0",
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)