from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.app.routes import scanner, dashboard

app = FastAPI(
    title="CloudPosture — CSPM Scanner",
    description="Cloud Security Posture Management tool for AWS misconfiguration detection",
    version="1.0.0",
)

# Mount static files
frontend_path = Path(__file__).parent.parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(frontend_path / "static")), name="static")

# Include routes
app.include_router(scanner.router, prefix="/api/scan", tags=["Scanner"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])


@app.get("/", include_in_schema=False)
async def serve_frontend():
    return FileResponse(str(frontend_path / "index.html"))


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "CloudPosture"}
