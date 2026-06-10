from __future__ import annotations

from fastapi import APIRouter
from backend.app.services.scanner_engine import run_scan
from backend.app.models.schemas import ScanRequest

router = APIRouter()

# Store latest scan result in memory
_latest_scan = None


@router.post("/run")
async def trigger_scan(request: ScanRequest = None):
    global _latest_scan
    categories = request.categories if request else None
    result = await run_scan(categories)
    _latest_scan = result
    return result


@router.get("/latest")
async def get_latest_scan():
    global _latest_scan
    if _latest_scan is None:
        _latest_scan = await run_scan(None)
    return _latest_scan


@router.get("/status")
async def scan_status():
    return {
        "has_results": _latest_scan is not None,
        "last_scan": _latest_scan.timestamp if _latest_scan else None,
    }
