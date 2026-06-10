import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app


@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_scan_run():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/scan/run", json={})
    assert response.status_code == 200
    data = response.json()
    assert data["total_checks"] > 0
    assert data["compliance_score"] >= 0
    assert len(data["findings"]) > 0


@pytest.mark.asyncio
async def test_dashboard_summary():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "compliance_score" in data
    assert "by_service" in data
    assert "by_severity" in data


@pytest.mark.asyncio
async def test_findings_filter():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/dashboard/findings?severity=CRITICAL")
    assert response.status_code == 200
    data = response.json()
    for finding in data["findings"]:
        assert finding["severity"] == "CRITICAL"
