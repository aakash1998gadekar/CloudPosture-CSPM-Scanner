from fastapi import APIRouter
from backend.app.services.scanner_engine import run_scan

router = APIRouter()


@router.get("/summary")
async def get_dashboard_summary():
    result = await run_scan(None)
    return {
        "compliance_score": result.compliance_score,
        "total_checks": result.total_checks,
        "passed": result.passed,
        "failed": result.failed,
        "warnings": result.warnings,
        "by_service": result.summary_by_service,
        "by_severity": result.summary_by_severity,
        "critical_findings": [f.model_dump() for f in result.findings if f.severity == "CRITICAL"],
        "recent_findings": [f.model_dump() for f in result.findings[:20]],
    }


@router.get("/findings")
async def get_all_findings(service: str = None, severity: str = None):
    result = await run_scan(None)
    findings = result.findings

    if service:
        findings = [f for f in findings if f.service == service]
    if severity:
        findings = [f for f in findings if f.severity == severity]

    return {"total": len(findings), "findings": [f.model_dump() for f in findings]}


@router.get("/compliance")
async def get_compliance_breakdown():
    result = await run_scan(None)
    services = {}
    for finding in result.findings:
        svc = finding.service
        if svc not in services:
            services[svc] = {"passed": 0, "failed": 0, "total": 0}
        services[svc]["total"] += 1
        if finding.status == "PASS":
            services[svc]["passed"] += 1
        else:
            services[svc]["failed"] += 1

    for svc in services:
        total = services[svc]["total"]
        services[svc]["score"] = round((services[svc]["passed"] / total) * 100, 1) if total > 0 else 0

    return {"overall_score": result.compliance_score, "services": services}
