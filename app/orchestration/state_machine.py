from app.models.models import ScanStageType


STAGE_ORDER = [
    ScanStageType.TARGET_INPUT,
    ScanStageType.SUBDOMAIN_ENUM,
    ScanStageType.ALIVE_DETECTION,
    ScanStageType.URL_COLLECTION,
    ScanStageType.ENDPOINT_PARSING,
    ScanStageType.ATTACK_SURFACE_MODELING,
    ScanStageType.RISK_SCORING,
    ScanStageType.SMART_PRIORITIZATION,
    ScanStageType.ORCHESTRATION,
    ScanStageType.VULN_SCANNING,
    ScanStageType.PORT_SCANNING,
    ScanStageType.TECH_DETECTION,
    ScanStageType.SCREENSHOT,
    ScanStageType.NORMALIZATION,
    ScanStageType.STORAGE,
    ScanStageType.REPORTING,
    ScanStageType.DASHBOARD_EXPOSURE,
]


class InvalidTransition(Exception):
    pass


def next_stage(current: ScanStageType | None) -> ScanStageType | None:
    if current is None:
        return STAGE_ORDER[0]
    try:
        idx = STAGE_ORDER.index(current)
    except ValueError as exc:
        raise InvalidTransition(f"Unknown stage: {current}") from exc
    if idx + 1 >= len(STAGE_ORDER):
        return None
    return STAGE_ORDER[idx + 1]


def is_valid_transition(current: ScanStageType | None, nxt: ScanStageType) -> bool:
    expected = next_stage(current)
    return expected == nxt
