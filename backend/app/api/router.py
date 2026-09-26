from fastapi import APIRouter

from app.api.routes import (
    approvals,
    attack_paths,
    audit,
    auth,
    correlations,
    detection_as_code,
    detection_rules,
    detections,
    health,
    incident_memories,
    incident_reports,
    risks,
    soc,
    soar,
    threat_hunts,
    users,
)

api_router = APIRouter()


api_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health"],
)

api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"],
)

api_router.include_router(
    users.router,
    prefix="/users",
    tags=["Users"],
)

api_router.include_router(
    audit.router,
    prefix="/audit",
    tags=["Audit"],
)

api_router.include_router(
    detections.router,
    prefix="/detections",
    tags=["Detections"],
)

api_router.include_router(
    detections.analyses_router,
    prefix="/detection-analyses",
    tags=["Detections"],
)

api_router.include_router(
    detection_rules.router,
    prefix="/detection-rules",
    tags=["Detections"],
)

api_router.include_router(
    detection_as_code.router,
    prefix="/detection-as-code",
    tags=["Detections"],
)

api_router.include_router(
    correlations.router,
    prefix="/correlations",
    tags=["Correlations"],
)

api_router.include_router(
    risks.router,
    prefix="/risk-assessments",
    tags=["Risk Assessments"],
)

api_router.include_router(
    incident_memories.router,
    prefix="/incident-memories",
    tags=["Incident Memories"],
)

api_router.include_router(
    approvals.router,
    prefix="/approvals",
    tags=["Approvals"],
)

api_router.include_router(
    soar.router,
    prefix="/soar",
    tags=["SOAR"],
)

api_router.include_router(
    threat_hunts.router,
    prefix="/threat-hunts",
    tags=["Threat Hunting"],
)

api_router.include_router(
    incident_reports.router,
    prefix="/incident-reports",
    tags=["Incident Reports"],
)

api_router.include_router(
    attack_paths.router,
    prefix="/attack-paths",
    tags=["Attack Paths"],
)

api_router.include_router(
    soc.router,
    prefix="/soc",
    tags=["Natural Language SOC"],
)